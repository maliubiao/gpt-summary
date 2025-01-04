Response: The user wants a summary of the provided C++ code, which is a part of the V8 JavaScript engine's test suite. Specifically, this is the 8th part of a larger file testing the ARM64 assembler.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `test-assembler-arm64.cc` strongly suggests this code tests the ARM64 assembler within V8. The `TEST` macros further confirm this, indicating unit tests.

2. **Analyze the Test Names:**  The names of the test functions are highly informative. Look for recurring themes and keywords:
    * `process_nans_double`, `process_nans_float`: Clearly tests how the assembler handles NaN (Not-a-Number) values in floating-point operations (both double and single precision).
    * `default_nan_float`, `default_nan_double`: Tests the "default NaN" behavior, which likely involves how NaNs are generated or handled when certain configurations are set.
    * `near_call_no_relocation`: Tests the `near_call` instruction, focusing on cases where relocation (adjusting addresses during linking) is not needed.
    * `abs`: Tests the absolute value instruction.
    * `pool_size`:  Relates to memory management and how the assembler handles constant and veneer pools (regions of memory for constants and small code snippets).
    * `jump_tables_forward`, `jump_tables_backward`: Tests the implementation of jump tables, crucial for efficient branching in code. The "forward" and "backward" likely refer to the direction of the jumps in memory.
    * `internal_reference_linked`: Tests how the assembler handles internal references, especially when these references are linked through multiple labels.
    * `scalar_movi`: Tests the `movi` instruction for moving immediate values to scalar (single) registers.
    * `neon_pmull`, `neon_3extension_dot_product`: Tests specific ARM64 NEON (SIMD) instructions for polynomial multiplication and dot product. The "3extension" hints at a specific architectural extension.
    * `vector_fp16_*`: Tests various floating-point operations specifically for the FP16 (half-precision floating-point) data type.

3. **Group Related Tests:** The test names naturally group into functional areas: NaN handling, function calls, arithmetic operations, memory management (pools), control flow (jump tables), and SIMD/FP16 instructions.

4. **Infer Functionality from Test Logic:** Even without deep knowledge of the V8 codebase, the code within each `TEST` function provides clues. For example, the `ProcessNaNsHelper` function being called with different NaN values and then checking the results suggests a test of NaN propagation rules. The `DefaultNaNHelper` setting the `DN_mask` in the `FPCR` register points to testing a specific floating-point control register behavior.

5. **Identify JavaScript Relevance:**  Since this is part of V8, it directly relates to how JavaScript code is compiled and executed. Focus on areas where the assembler directly implements JavaScript features or optimizations. Key areas include:
    * Floating-point number handling (JavaScript numbers are doubles by default).
    * Function calls.
    * Optimizations like jump tables.
    * SIMD instructions can be used to optimize certain JavaScript operations.

6. **Construct JavaScript Examples:**  For the relevant areas, create simple JavaScript snippets that would trigger the underlying assembler code being tested. Keep the examples concise and focused on demonstrating the specific functionality. For instance, using `NaN`, performing arithmetic with NaNs, calling functions, and using typed arrays (which can leverage SIMD).

7. **Structure the Summary:** Organize the findings logically, starting with a high-level overview, then detailing the tested areas, and finally providing JavaScript examples. Use clear and concise language.

8. **Address the "Part 8 of 8" Information:** Acknowledge that this is the final part, implying it covers the remaining test cases not covered in previous parts. This reinforces that the summary should encompass the specific tests in this file.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Simply list all the test names. **Correction:** This is too granular. Grouping by functionality provides a better high-level understanding.
* **Initial thought:**  Focus only on the C++ code. **Correction:** The prompt specifically asks about the relationship to JavaScript. Need to make that connection explicit with examples.
* **Initial thought:** Provide very technical details about the ARM64 instructions. **Correction:** The summary should be understandable to someone with a general understanding of programming and JavaScript, not just ARM64 assembly experts. Focus on the *purpose* of the tests rather than the intricate details of each instruction.
* **Initial thought:**  Overlook the "part 8 of 8" information. **Correction:**  Include this to provide context and completeness.
好的，让我们来归纳一下 `v8/test/cctest/test-assembler-arm64.cc` 文件第 8 部分的功能。

**功能归纳:**

这个 C++ 代码文件是 V8 JavaScript 引擎测试套件的一部分，专门用于测试 ARM64 架构下的汇编器 (`Assembler`) 的功能。作为第 8 部分，它延续了对汇编器各种指令和特性的测试，主要集中在以下几个方面：

1. **浮点数 NaN (Not-a-Number) 的处理:**
   - 测试了在浮点运算中 NaN 值的传播规则，包括 Signaling NaN 和 Quiet NaN 的处理。
   - 测试了在启用“默认 NaN 模式”时，各种浮点运算指令（包括一元和二元运算以及 fused multiply-add 等）如何产生默认的 NaN 值。

2. **近距离函数调用 (`near_call`)：**
   - 测试了在不需要重定位的情况下，`near_call` 指令的正确性。

3. **绝对值指令 (`Abs`)：**
   - 测试了 `Abs` 指令对于有符号整数（32 位和 64 位）计算绝对值的各种情况，包括最小值的情况。

4. **常量池和 Veneer 池的大小 (`pool_size`)：**
   - 测试了如何记录和读取常量池和 Veneer 池的大小信息。这部分代码本身不执行，而是检查生成的代码描述中是否正确记录了池的大小。

5. **跳转表 (`jump_tables_forward`, `jump_tables_backward`)：**
   - 测试了使用跳转表实现多路分支的功能，包括向前跳转和向后跳转的情况。

6. **内部引用链接 (`internal_reference_linked`)：**
   - 测试了当内部引用链接在一个标签链中时，汇编器的处理是否正确。

7. **标量 MOVI 指令 (`scalar_movi`)：**
   - 测试了将立即数移动到标量寄存器的 `Movi` 指令。

8. **NEON 指令测试：**
   - 测试了 `PMULL` (Polynomial Multiply Long) 和 `SDOT` (Signed Dot Product) 等 NEON (Advanced SIMD) 指令的功能。

9. **半精度浮点数 (FP16) 指令测试 (`vector_fp16_*`)：**
   - 测试了各种针对半精度浮点数的向量运算指令，例如 `fadd`、`fsub`、`fmul`、`fdiv`、`fmax`、`fmin`、`fabs`、`fsqrt`、`fneg`、`frintp` 等。

**与 JavaScript 功能的关系及 JavaScript 例子：**

这个测试文件直接测试了 V8 引擎中将 JavaScript 代码编译成 ARM64 机器码的关键部分。汇编器的正确性直接影响了 JavaScript 代码的执行效率和准确性。

以下是一些 JavaScript 例子，它们在 V8 内部的编译过程中可能会涉及到这里测试的汇编指令：

**1. NaN 的处理:**

```javascript
console.log(NaN + 5);       // 输出 NaN
console.log(NaN > 5);       // 输出 false
console.log(Math.max(NaN, 10)); // 输出 10 (取决于具体的实现，有的会返回 NaN)
```

V8 的汇编器需要正确实现浮点数运算的 NaN 传播规则，确保 JavaScript 中涉及 NaN 的运算得到预期的结果。

**2. 函数调用:**

```javascript
function add(a, b) {
  return a + b;
}

add(2, 3);
```

当 V8 编译 `add(2, 3)` 这个函数调用时，会生成汇编代码来进行参数传递和跳转到函数体。 `near_call` 的测试确保了这种近距离的函数调用机制的正确性。

**3. 绝对值运算:**

```javascript
console.log(Math.abs(-5));  // 输出 5
console.log(Math.abs(5));   // 输出 5
```

`Math.abs()` 函数在底层会使用汇编器的绝对值指令，例如 `Abs`。

**4. 跳转表 (用于 switch 语句或优化的对象属性访问):**

```javascript
function handleCase(value) {
  switch (value) {
    case 0:
      console.log("Case 0");
      break;
    case 1:
      console.log("Case 1");
      break;
    case 2:
      console.log("Case 2");
      break;
    // ... 更多 case
    default:
      console.log("Default case");
  }
}

handleCase(1);
```

V8 在编译 `switch` 语句时，可能会使用跳转表来优化分支逻辑，提高执行效率。

**5. NEON 指令 (用于优化数组或 TypedArray 的运算):**

```javascript
const arr1 = new Float32Array([1, 2, 3, 4]);
const arr2 = new Float32Array([5, 6, 7, 8]);
const result = new Float32Array(4);

for (let i = 0; i < arr1.length; i++) {
  result[i] = arr1[i] * arr2[i];
}
console.log(result); // 输出 Float32Array [ 5, 12, 21, 32 ]
```

对于涉及大量数值计算的 JavaScript 代码，特别是使用 `TypedArray` 时，V8 可能会利用 NEON 指令进行 SIMD (单指令多数据) 优化，例如向量化的乘法和加法等。 `neon_pmull` 和 `neon_3extension_dot_product` 的测试确保了这些优化手段的正确性。

**6. 半精度浮点数 (在 WebGL 等场景中可能用到):**

虽然 JavaScript 的 `Number` 类型是双精度浮点数，但在某些特定场景下，例如 WebGL，可能会使用半精度浮点数来提高性能和减少内存占用。 `vector_fp16_*` 的测试确保了 V8 对这些半精度浮点数运算指令的支持。

**总结:**

`v8/test/cctest/test-assembler-arm64.cc` 的第 8 部分专注于测试 ARM64 汇编器在处理浮点数 NaN、函数调用、绝对值运算、内存池管理、跳转表、内部引用、标量 MOVI 指令以及各种 NEON 和半精度浮点数指令时的正确性。这些测试对于确保 V8 能够高效且准确地将 JavaScript 代码编译成在 ARM64 架构上运行的机器码至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共8部分，请归纳一下它的功能

"""
d, d6);
  CHECK_EQUAL_FP64(expected, d7);
}

TEST(process_nans_double) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  double sn = base::bit_cast<double>(0x7FF5555511111111);
  double sm = base::bit_cast<double>(0x7FF5555522222222);
  double qn = base::bit_cast<double>(0x7FFAAAAA11111111);
  double qm = base::bit_cast<double>(0x7FFAAAAA22222222);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsSignallingNaN(sm));
  CHECK(IsQuietNaN(qn));
  CHECK(IsQuietNaN(qm));

  // The input NaNs after passing through ProcessNaN.
  double sn_proc = base::bit_cast<double>(0x7FFD555511111111);
  double sm_proc = base::bit_cast<double>(0x7FFD555522222222);
  double qn_proc = qn;
  double qm_proc = qm;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(sm_proc));
  CHECK(IsQuietNaN(qn_proc));
  CHECK(IsQuietNaN(qm_proc));

  // Quiet NaNs are propagated.
  ProcessNaNsHelper(qn, 0, qn_proc);
  ProcessNaNsHelper(0, qm, qm_proc);
  ProcessNaNsHelper(qn, qm, qn_proc);

  // Signalling NaNs are propagated, and made quiet.
  ProcessNaNsHelper(sn, 0, sn_proc);
  ProcessNaNsHelper(0, sm, sm_proc);
  ProcessNaNsHelper(sn, sm, sn_proc);

  // Signalling NaNs take precedence over quiet NaNs.
  ProcessNaNsHelper(sn, qm, sn_proc);
  ProcessNaNsHelper(qn, sm, sm_proc);
  ProcessNaNsHelper(sn, sm, sn_proc);
}

static void ProcessNaNsHelper(float n, float m, float expected) {
  CHECK(std::isnan(n) || std::isnan(m));
  CHECK(std::isnan(expected));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaNs, and check that
  // they all propagate NaNs correctly.
  __ Fmov(s0, n);
  __ Fmov(s1, m);

  __ Fadd(s2, s0, s1);
  __ Fsub(s3, s0, s1);
  __ Fmul(s4, s0, s1);
  __ Fdiv(s5, s0, s1);
  __ Fmax(s6, s0, s1);
  __ Fmin(s7, s0, s1);

  END();
  RUN();

  CHECK_EQUAL_FP32(expected, s2);
  CHECK_EQUAL_FP32(expected, s3);
  CHECK_EQUAL_FP32(expected, s4);
  CHECK_EQUAL_FP32(expected, s5);
  CHECK_EQUAL_FP32(expected, s6);
  CHECK_EQUAL_FP32(expected, s7);
}

TEST(process_nans_float) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  float sn = base::bit_cast<float>(0x7F951111);
  float sm = base::bit_cast<float>(0x7F952222);
  float qn = base::bit_cast<float>(0x7FEA1111);
  float qm = base::bit_cast<float>(0x7FEA2222);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsSignallingNaN(sm));
  CHECK(IsQuietNaN(qn));
  CHECK(IsQuietNaN(qm));

  // The input NaNs after passing through ProcessNaN.
  float sn_proc = base::bit_cast<float>(0x7FD51111);
  float sm_proc = base::bit_cast<float>(0x7FD52222);
  float qn_proc = qn;
  float qm_proc = qm;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(sm_proc));
  CHECK(IsQuietNaN(qn_proc));
  CHECK(IsQuietNaN(qm_proc));

  // Quiet NaNs are propagated.
  ProcessNaNsHelper(qn, 0, qn_proc);
  ProcessNaNsHelper(0, qm, qm_proc);
  ProcessNaNsHelper(qn, qm, qn_proc);

  // Signalling NaNs are propagated, and made quiet.
  ProcessNaNsHelper(sn, 0, sn_proc);
  ProcessNaNsHelper(0, sm, sm_proc);
  ProcessNaNsHelper(sn, sm, sn_proc);

  // Signalling NaNs take precedence over quiet NaNs.
  ProcessNaNsHelper(sn, qm, sn_proc);
  ProcessNaNsHelper(qn, sm, sm_proc);
  ProcessNaNsHelper(sn, sm, sn_proc);
}

static void DefaultNaNHelper(float n, float m, float a) {
  CHECK(std::isnan(n) || std::isnan(m) || std::isnan(a));

  bool test_1op = std::isnan(n);
  bool test_2op = std::isnan(n) || std::isnan(m);

  SETUP();
  START();

  // Enable Default-NaN mode in the FPCR.
  __ Mrs(x0, FPCR);
  __ Orr(x1, x0, DN_mask);
  __ Msr(FPCR, x1);

  // Execute a number of instructions which all use ProcessNaNs, and check that
  // they all produce the default NaN.
  __ Fmov(s0, n);
  __ Fmov(s1, m);
  __ Fmov(s2, a);

  if (test_1op) {
    // Operations that always propagate NaNs unchanged, even signalling NaNs.
    __ Fmov(s10, s0);
    __ Fabs(s11, s0);
    __ Fneg(s12, s0);

    // Operations that use ProcessNaN.
    __ Fsqrt(s13, s0);
    __ Frinta(s14, s0);
    __ Frintn(s15, s0);
    __ Frintz(s16, s0);

    // Fcvt usually has special NaN handling, but it respects default-NaN mode.
    __ Fcvt(d17, s0);
  }

  if (test_2op) {
    __ Fadd(s18, s0, s1);
    __ Fsub(s19, s0, s1);
    __ Fmul(s20, s0, s1);
    __ Fdiv(s21, s0, s1);
    __ Fmax(s22, s0, s1);
    __ Fmin(s23, s0, s1);
  }

  __ Fmadd(s24, s0, s1, s2);
  __ Fmsub(s25, s0, s1, s2);
  __ Fnmadd(s26, s0, s1, s2);
  __ Fnmsub(s27, s0, s1, s2);

  // Restore FPCR.
  __ Msr(FPCR, x0);

  END();
  RUN();

  if (test_1op) {
    uint32_t n_raw = base::bit_cast<uint32_t>(n);
    uint32_t sign_mask = static_cast<uint32_t>(kSSignMask);
    CHECK_EQUAL_FP32(n, s10);
    CHECK_EQUAL_FP32(base::bit_cast<float>(n_raw & ~sign_mask), s11);
    CHECK_EQUAL_FP32(base::bit_cast<float>(n_raw ^ sign_mask), s12);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s13);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s14);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s15);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s16);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d17);
  }

  if (test_2op) {
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s18);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s19);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s20);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s21);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s22);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s23);
  }

  CHECK_EQUAL_FP32(kFP32DefaultNaN, s24);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s25);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s26);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s27);
}

TEST(default_nan_float) {
  INIT_V8();
  float sn = base::bit_cast<float>(0x7F951111);
  float sm = base::bit_cast<float>(0x7F952222);
  float sa = base::bit_cast<float>(0x7F95AAAA);
  float qn = base::bit_cast<float>(0x7FEA1111);
  float qm = base::bit_cast<float>(0x7FEA2222);
  float qa = base::bit_cast<float>(0x7FEAAAAA);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsSignallingNaN(sm));
  CHECK(IsSignallingNaN(sa));
  CHECK(IsQuietNaN(qn));
  CHECK(IsQuietNaN(qm));
  CHECK(IsQuietNaN(qa));

  //   - Signalling NaNs
  DefaultNaNHelper(sn, 0.0f, 0.0f);
  DefaultNaNHelper(0.0f, sm, 0.0f);
  DefaultNaNHelper(0.0f, 0.0f, sa);
  DefaultNaNHelper(sn, sm, 0.0f);
  DefaultNaNHelper(0.0f, sm, sa);
  DefaultNaNHelper(sn, 0.0f, sa);
  DefaultNaNHelper(sn, sm, sa);
  //   - Quiet NaNs
  DefaultNaNHelper(qn, 0.0f, 0.0f);
  DefaultNaNHelper(0.0f, qm, 0.0f);
  DefaultNaNHelper(0.0f, 0.0f, qa);
  DefaultNaNHelper(qn, qm, 0.0f);
  DefaultNaNHelper(0.0f, qm, qa);
  DefaultNaNHelper(qn, 0.0f, qa);
  DefaultNaNHelper(qn, qm, qa);
  //   - Mixed NaNs
  DefaultNaNHelper(qn, sm, sa);
  DefaultNaNHelper(sn, qm, sa);
  DefaultNaNHelper(sn, sm, qa);
  DefaultNaNHelper(qn, qm, sa);
  DefaultNaNHelper(sn, qm, qa);
  DefaultNaNHelper(qn, sm, qa);
  DefaultNaNHelper(qn, qm, qa);
}

static void DefaultNaNHelper(double n, double m, double a) {
  CHECK(std::isnan(n) || std::isnan(m) || std::isnan(a));

  bool test_1op = std::isnan(n);
  bool test_2op = std::isnan(n) || std::isnan(m);

  SETUP();
  START();

  // Enable Default-NaN mode in the FPCR.
  __ Mrs(x0, FPCR);
  __ Orr(x1, x0, DN_mask);
  __ Msr(FPCR, x1);

  // Execute a number of instructions which all use ProcessNaNs, and check that
  // they all produce the default NaN.
  __ Fmov(d0, n);
  __ Fmov(d1, m);
  __ Fmov(d2, a);

  if (test_1op) {
    // Operations that always propagate NaNs unchanged, even signalling NaNs.
    __ Fmov(d10, d0);
    __ Fabs(d11, d0);
    __ Fneg(d12, d0);

    // Operations that use ProcessNaN.
    __ Fsqrt(d13, d0);
    __ Frinta(d14, d0);
    __ Frintn(d15, d0);
    __ Frintz(d16, d0);

    // Fcvt usually has special NaN handling, but it respects default-NaN mode.
    __ Fcvt(s17, d0);
  }

  if (test_2op) {
    __ Fadd(d18, d0, d1);
    __ Fsub(d19, d0, d1);
    __ Fmul(d20, d0, d1);
    __ Fdiv(d21, d0, d1);
    __ Fmax(d22, d0, d1);
    __ Fmin(d23, d0, d1);
  }

  __ Fmadd(d24, d0, d1, d2);
  __ Fmsub(d25, d0, d1, d2);
  __ Fnmadd(d26, d0, d1, d2);
  __ Fnmsub(d27, d0, d1, d2);

  // Restore FPCR.
  __ Msr(FPCR, x0);

  END();
  RUN();

  if (test_1op) {
    uint64_t n_raw = base::bit_cast<uint64_t>(n);
    CHECK_EQUAL_FP64(n, d10);
    CHECK_EQUAL_FP64(base::bit_cast<double>(n_raw & ~kDSignMask), d11);
    CHECK_EQUAL_FP64(base::bit_cast<double>(n_raw ^ kDSignMask), d12);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d13);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d14);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d15);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d16);
    CHECK_EQUAL_FP32(kFP32DefaultNaN, s17);
  }

  if (test_2op) {
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d18);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d19);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d20);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d21);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d22);
    CHECK_EQUAL_FP64(kFP64DefaultNaN, d23);
  }

  CHECK_EQUAL_FP64(kFP64DefaultNaN, d24);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d25);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d26);
  CHECK_EQUAL_FP64(kFP64DefaultNaN, d27);
}

TEST(default_nan_double) {
  INIT_V8();
  double sn = base::bit_cast<double>(0x7FF5555511111111);
  double sm = base::bit_cast<double>(0x7FF5555522222222);
  double sa = base::bit_cast<double>(0x7FF55555AAAAAAAA);
  double qn = base::bit_cast<double>(0x7FFAAAAA11111111);
  double qm = base::bit_cast<double>(0x7FFAAAAA22222222);
  double qa = base::bit_cast<double>(0x7FFAAAAAAAAAAAAA);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsSignallingNaN(sm));
  CHECK(IsSignallingNaN(sa));
  CHECK(IsQuietNaN(qn));
  CHECK(IsQuietNaN(qm));
  CHECK(IsQuietNaN(qa));

  //   - Signalling NaNs
  DefaultNaNHelper(sn, 0.0, 0.0);
  DefaultNaNHelper(0.0, sm, 0.0);
  DefaultNaNHelper(0.0, 0.0, sa);
  DefaultNaNHelper(sn, sm, 0.0);
  DefaultNaNHelper(0.0, sm, sa);
  DefaultNaNHelper(sn, 0.0, sa);
  DefaultNaNHelper(sn, sm, sa);
  //   - Quiet NaNs
  DefaultNaNHelper(qn, 0.0, 0.0);
  DefaultNaNHelper(0.0, qm, 0.0);
  DefaultNaNHelper(0.0, 0.0, qa);
  DefaultNaNHelper(qn, qm, 0.0);
  DefaultNaNHelper(0.0, qm, qa);
  DefaultNaNHelper(qn, 0.0, qa);
  DefaultNaNHelper(qn, qm, qa);
  //   - Mixed NaNs
  DefaultNaNHelper(qn, sm, sa);
  DefaultNaNHelper(sn, qm, sa);
  DefaultNaNHelper(sn, sm, qa);
  DefaultNaNHelper(qn, qm, sa);
  DefaultNaNHelper(sn, qm, qa);
  DefaultNaNHelper(qn, sm, qa);
  DefaultNaNHelper(qn, qm, qa);
}

TEST(near_call_no_relocation) {
  INIT_V8();
  SETUP();

  START();

  Label function;
  Label test;

  __ B(&test);

  __ Bind(&function);
  __ Mov(x0, 0x1);
  __ Ret();

  __ Bind(&test);
  __ Mov(x0, 0x0);
  {
    Assembler::BlockConstPoolScope scope(&masm);
    int offset = (function.pos() - __ pc_offset()) / kInstrSize;
    __ near_call(offset, RelocInfo::NO_INFO);
  }
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
}

static void AbsHelperX(int64_t value) {
  int64_t expected;

  SETUP();
  START();

  Label fail;
  Label done;

  __ Mov(x0, 0);
  __ Mov(x1, value);

  if (value != kXMinInt) {
    expected = std::abs(value);

    Label next;
    // The result is representable.
    __ Abs(x10, x1);
    __ Abs(x11, x1, &fail);
    __ Abs(x12, x1, &fail, &next);
    __ Bind(&next);
    __ Abs(x13, x1, nullptr, &done);
  } else {
    // std::abs is undefined for kXMinInt but our implementation in the
    // MacroAssembler will return kXMinInt in such a case.
    expected = kXMinInt;

    Label next;
    // The result is not representable.
    __ Abs(x10, x1);
    __ Abs(x11, x1, nullptr, &fail);
    __ Abs(x12, x1, &next, &fail);
    __ Bind(&next);
    __ Abs(x13, x1, &done);
  }

  __ Bind(&fail);
  __ Mov(x0, -1);

  __ Bind(&done);

  END();
  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(value, x1);
  CHECK_EQUAL_64(expected, x10);
  CHECK_EQUAL_64(expected, x11);
  CHECK_EQUAL_64(expected, x12);
  CHECK_EQUAL_64(expected, x13);
}


static void AbsHelperW(int32_t value) {
  int32_t expected;

  SETUP();
  START();

  Label fail;
  Label done;

  __ Mov(w0, 0);
  // TODO(jbramley): The cast is needed to avoid a sign-extension bug in VIXL.
  // Once it is fixed, we should remove the cast.
  __ Mov(w1, static_cast<uint32_t>(value));

  if (value != kWMinInt) {
    expected = abs(value);

    Label next;
    // The result is representable.
    __ Abs(w10, w1);
    __ Abs(w11, w1, &fail);
    __ Abs(w12, w1, &fail, &next);
    __ Bind(&next);
    __ Abs(w13, w1, nullptr, &done);
  } else {
    // abs is undefined for kWMinInt but our implementation in the
    // MacroAssembler will return kWMinInt in such a case.
    expected = kWMinInt;

    Label next;
    // The result is not representable.
    __ Abs(w10, w1);
    __ Abs(w11, w1, nullptr, &fail);
    __ Abs(w12, w1, &next, &fail);
    __ Bind(&next);
    __ Abs(w13, w1, &done);
  }

  __ Bind(&fail);
  __ Mov(w0, -1);

  __ Bind(&done);

  END();
  RUN();

  CHECK_EQUAL_32(0, w0);
  CHECK_EQUAL_32(value, w1);
  CHECK_EQUAL_32(expected, w10);
  CHECK_EQUAL_32(expected, w11);
  CHECK_EQUAL_32(expected, w12);
  CHECK_EQUAL_32(expected, w13);
}

TEST(abs) {
  INIT_V8();
  AbsHelperX(0);
  AbsHelperX(42);
  AbsHelperX(-42);
  AbsHelperX(kXMinInt);
  AbsHelperX(kXMaxInt);

  AbsHelperW(0);
  AbsHelperW(42);
  AbsHelperW(-42);
  AbsHelperW(kWMinInt);
  AbsHelperW(kWMaxInt);
}

TEST(pool_size) {
  INIT_V8();
  SETUP();

  // This test does not execute any code. It only tests that the size of the
  // pools is read correctly from the RelocInfo.

  Label exit;
  __ b(&exit);

  const unsigned constant_pool_size = 312;
  const unsigned veneer_pool_size = 184;

  __ RecordConstPool(constant_pool_size);
  for (unsigned i = 0; i < constant_pool_size / 4; ++i) {
    __ dc32(0);
  }

  __ RecordVeneerPool(masm.pc_offset(), veneer_pool_size);
  for (unsigned i = 0; i < veneer_pool_size / kInstrSize; ++i) {
    __ nop();
  }

  __ bind(&exit);

  CodeDesc desc;
  masm.GetCode(isolate, &desc);
  code = Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING)
             .set_self_reference(masm.CodeObject())
             .Build();

  unsigned pool_count = 0;
  int pool_mask = RelocInfo::ModeMask(RelocInfo::CONST_POOL) |
                  RelocInfo::ModeMask(RelocInfo::VENEER_POOL);
  for (RelocIterator it(*code, pool_mask); !it.done(); it.next()) {
    RelocInfo* info = it.rinfo();
    if (RelocInfo::IsConstPool(info->rmode())) {
      CHECK_EQ(info->data(), constant_pool_size);
      ++pool_count;
    }
    if (RelocInfo::IsVeneerPool(info->rmode())) {
      CHECK_EQ(info->data(), veneer_pool_size);
      ++pool_count;
    }
  }

  CHECK_EQ(pool_count, 2);
}

TEST(jump_tables_forward) {
  // Test jump tables with forward jumps.
  const int kNumCases = 512;

  INIT_V8();
  SETUP_SIZE(kNumCases * 5 * kInstrSize + 8192);
  START();

  int32_t values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  int32_t results[kNumCases];
  memset(results, 0, sizeof(results));
  uintptr_t results_ptr = reinterpret_cast<uintptr_t>(results);

  Label loop;
  Label labels[kNumCases];
  Label done;

  const Register& index = x0;
  static_assert(sizeof(results[0]) == 4);
  const Register& value = w1;
  const Register& target = x2;

  __ Mov(index, 0);
  __ Mov(target, results_ptr);
  __ Bind(&loop);

  {
    Assembler::BlockPoolsScope block_pools(&masm);
    Label base;

    __ Adr(x10, &base);
    __ Ldr(x11, MemOperand(x10, index, LSL, kSystemPointerSizeLog2));
    __ Br(x11);
    __ Bind(&base);
    for (int i = 0; i < kNumCases; ++i) {
      __ dcptr(&labels[i]);
    }
  }

  for (int i = 0; i < kNumCases; ++i) {
    __ Bind(&labels[i], BranchTargetIdentifier::kBtiJump);
    __ Mov(value, values[i]);
    __ B(&done);
  }

  __ Bind(&done);
  __ Str(value, MemOperand(target, 4, PostIndex));
  __ Add(index, index, 1);
  __ Cmp(index, kNumCases);
  __ B(ne, &loop);

  END();

  RUN();

  for (int i = 0; i < kNumCases; ++i) {
    CHECK_EQ(values[i], results[i]);
  }
}

TEST(jump_tables_backward) {
  // Test jump tables with backward jumps.
  const int kNumCases = 512;

  INIT_V8();
  SETUP_SIZE(kNumCases * 5 * kInstrSize + 8192);
  START();

  int32_t values[kNumCases];
  isolate->random_number_generator()->NextBytes(values, sizeof(values));
  int32_t results[kNumCases];
  memset(results, 0, sizeof(results));
  uintptr_t results_ptr = reinterpret_cast<uintptr_t>(results);

  Label loop;
  Label labels[kNumCases];
  Label done;

  const Register& index = x0;
  static_assert(sizeof(results[0]) == 4);
  const Register& value = w1;
  const Register& target = x2;

  __ Mov(index, 0);
  __ Mov(target, results_ptr);
  __ B(&loop);

  for (int i = 0; i < kNumCases; ++i) {
    __ Bind(&labels[i], BranchTargetIdentifier::kBtiJump);
    __ Mov(value, values[i]);
    __ B(&done);
  }

  __ Bind(&loop);
  {
    Assembler::BlockPoolsScope block_pools(&masm);
    Label base;

    __ Adr(x10, &base);
    __ Ldr(x11, MemOperand(x10, index, LSL, kSystemPointerSizeLog2));
    __ Br(x11);
    __ Bind(&base);
    for (int i = 0; i < kNumCases; ++i) {
      __ dcptr(&labels[i]);
    }
  }

  __ Bind(&done);
  __ Str(value, MemOperand(target, 4, PostIndex));
  __ Add(index, index, 1);
  __ Cmp(index, kNumCases);
  __ B(ne, &loop);

  END();

  RUN();

  for (int i = 0; i < kNumCases; ++i) {
    CHECK_EQ(values[i], results[i]);
  }
}

TEST(internal_reference_linked) {
  // Test internal reference when they are linked in a label chain.

  INIT_V8();
  SETUP();
  START();

  Label done;

  __ Mov(x0, 0);
  __ Cbnz(x0, &done);

  {
    Assembler::BlockPoolsScope block_pools(&masm);
    Label base;

    __ Adr(x10, &base);
    __ Ldr(x11, MemOperand(x10));
    __ Br(x11);
    __ Bind(&base);
    __ dcptr(&done);
  }

  // Dead code, just to extend the label chain.
  __ B(&done);
  __ dcptr(&done);
  __ Tbz(x0, 1, &done);

  __ Bind(&done, BranchTargetIdentifier::kBtiJump);
  __ Mov(x0, 1);

  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
}

TEST(scalar_movi) {
  INIT_V8();
  SETUP();
  START();

  // Make sure that V0 is initialized to a non-zero value.
  __ Movi(v0.V16B(), 0xFF);
  // This constant value can't be encoded in a MOVI instruction,
  // so the program would use a fallback path that must set the
  // upper 64 bits of the destination vector to 0.
  __ Movi(v0.V1D(), 0xDECAFC0FFEE);
  __ Mov(x0, v0.V2D(), 1);

  END();
  RUN();

  CHECK_EQUAL_64(0, x0);
}

TEST(neon_pmull) {
  INIT_V8();
  SETUP();
  SETUP_FEATURE(PMULL1Q);
  START();

  __ Movi(v0.V2D(), 0xDECAFC0FFEE);
  __ Movi(v1.V8H(), 0xBEEF);
  __ Movi(v2.V8H(), 0xC0DE);
  __ Movi(v3.V16B(), 42);

  __ Pmull(v0.V8H(), v0.V8B(), v0.V8B());
  __ Pmull2(v1.V8H(), v1.V16B(), v1.V16B());
  __ Pmull(v2.V1Q(), v2.V1D(), v2.V1D());
  __ Pmull2(v3.V1Q(), v3.V2D(), v3.V2D());

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_128(0x515450, 0x4455500055555454, q0);
    CHECK_EQUAL_128(0x4554545545545455, 0x4554545545545455, q1);
    CHECK_EQUAL_128(0x5000515450005154, 0x5000515450005154, q2);
    CHECK_EQUAL_128(0x444044404440444, 0x444044404440444, q3);
  }
}

TEST(neon_3extension_dot_product) {
  INIT_V8();
  SETUP();
  SETUP_FEATURE(DOTPROD);
  START();

  __ Movi(v0.V2D(), 0x7122712271227122, 0x7122712271227122);
  __ Movi(v1.V2D(), 0xe245e245f245f245, 0xe245e245f245f245);
  __ Movi(v2.V2D(), 0x3939393900000000, 0x3939393900000000);

  __ Movi(v16.V2D(), 0x0000400000004000, 0x0000400000004000);
  __ Movi(v17.V2D(), 0x0000400000004000, 0x0000400000004000);

  __ Sdot(v16.V4S(), v0.V16B(), v1.V16B());
  __ Sdot(v17.V2S(), v1.V8B(), v2.V8B());

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_128(0x000037d8000045f8, 0x000037d8000045f8, q16);
    CHECK_EQUAL_128(0, 0x0000515e00004000, q17);
  }
}

#define FP16_OP_LIST(V) \
  V(fadd)               \
  V(fsub)               \
  V(fmul)               \
  V(fdiv)               \
  V(fmax)               \
  V(fmin)

namespace {

float f16_round(float f) {
  return fp16_ieee_to_fp32_value(fp16_ieee_from_fp32_value(f));
}

float fadd(float a, float b) { return a + b; }

float fsub(float a, float b) { return a - b; }

float fmul(float a, float b) { return a * b; }

float fdiv(float a, float b) { return a / b; }

float fmax(float a, float b) { return a > b ? a : b; }

float fmin(float a, float b) { return a < b ? a : b; }
}  // namespace

#define TEST_FP16_OP(op)                                             \
  TEST(vector_fp16_##op) {                                           \
    INIT_V8();                                                       \
    SETUP();                                                         \
    SETUP_FEATURE(FP16);                                             \
    START();                                                         \
    float a = 42.15;                                                 \
    float b = 13.31;                                                 \
    __ Fmov(s0, a);                                                  \
    __ Fcvt(s0.H(), s0.S());                                         \
    __ Dup(v0.V8H(), v0.H(), 0);                                     \
    __ Fmov(s1, b);                                                  \
    __ Fcvt(s1.H(), s1.S());                                         \
    __ Dup(v1.V8H(), v1.H(), 0);                                     \
    __ op(v2.V8H(), v0.V8H(), v1.V8H());                             \
    END();                                                           \
    if (CAN_RUN()) {                                                 \
      RUN();                                                         \
      uint64_t res =                                                 \
          fp16_ieee_from_fp32_value(op(f16_round(a), f16_round(b))); \
      uint64_t half = res | (res << 16) | (res << 32) | (res << 48); \
      CHECK_EQUAL_128(half, half, v2);                               \
    }                                                                \
  }

FP16_OP_LIST(TEST_FP16_OP)

#undef TEST_FP16_OP
#undef FP16_OP_LIST

#define FP16_OP_LIST(V) \
  V(fabs, std::abs)     \
  V(fsqrt, std::sqrt)   \
  V(fneg, -)            \
  V(frintp, ceilf)

#define TEST_FP16_OP(op, cop)                                        \
  TEST(vector_fp16_##op) {                                           \
    INIT_V8();                                                       \
    SETUP();                                                         \
    SETUP_FEATURE(FP16);                                             \
    START();                                                         \
    float f = 42.15f16;                                              \
    __ Fmov(s0, f);                                                  \
    __ Fcvt(s0.H(), s0.S());                                         \
    __ Dup(v0.V8H(), v0.H(), 0);                                     \
    __ op(v1.V8H(), v0.V8H());                                       \
    END();                                                           \
    if (CAN_RUN()) {                                                 \
      RUN();                                                         \
      uint64_t res = fp16_ieee_from_fp32_value(cop(f16_round(f)));   \
      uint64_t half = res | (res << 16) | (res << 32) | (res << 48); \
      CHECK_EQUAL_128(half, half, v1);                               \
    }                                                                \
  }

FP16_OP_LIST(TEST_FP16_OP)

#undef TEST_FP16_OP
#undef FP16_OP_LIST

}  // namespace internal
}  // namespace v8

#undef __
#undef BUF_SIZE
#undef SETUP
#undef INIT_V8
#undef SETUP_SIZE
#undef RESET
#undef START_AFTER_RESET
#undef START
#undef RUN
#undef END
#undef CHECK_EQUAL_NZCV
#undef CHECK_EQUAL_REGISTERS
#undef CHECK_EQUAL_32
#undef CHECK_EQUAL_FP32
#undef CHECK_EQUAL_64
#undef CHECK_FULL_HEAP_OBJECT_IN_REGISTER
#undef CHECK_NOT_ZERO_AND_NOT_EQUAL_64
#undef CHECK_EQUAL_FP64
#undef CHECK_EQUAL_128
#undef CHECK_CONSTANT_POOL_SIZE

"""


```