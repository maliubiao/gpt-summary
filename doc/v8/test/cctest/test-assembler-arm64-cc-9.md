Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the File Type and Purpose:** The path `v8/test/cctest/test-assembler-arm64.cc` strongly suggests this is a test file for the ARM64 assembler within the V8 JavaScript engine. The `.cc` extension confirms it's C++. The name `test-assembler-arm64.cc` clearly indicates it tests the ARM64 assembler.

2. **Scan for Key Keywords and Patterns:** I look for recurring keywords and patterns that reveal the code's structure and functionality. I see:
    * `TEST(...) { ... }`: This is a common pattern in C++ testing frameworks (likely Google Test, which V8 uses). Each `TEST` block defines an individual test case.
    * `INIT_V8();`:  Suggests initialization of the V8 environment for testing.
    * `SETUP();`: Likely sets up the test environment for a specific test case.
    * `START();`: Probably initiates the assembly code generation.
    * `__ Fmov(...)`:  This strongly suggests assembly instructions, specifically for moving floating-point values. The `__` prefix is often used in V8's assembler DSL (Domain Specific Language).
    * `__ Frint...`, `__ Fcvt...`: More floating-point assembly instructions. The prefixes hint at different rounding modes (`rinta`, `rintm`, `rintn`, `rintp`, `rintz`) and conversions (`fcvt_ds`, `fcvt_sd`, `fcvtas`, etc.).
    * `END();`: Likely marks the end of the assembly code generation block.
    * `RUN();`: Executes the generated assembly code.
    * `CHECK_EQUAL_FP32(...)`, `CHECK_EQUAL_FP64(...)`, `CHECK_EQUAL_64(...)`, `CHECK_EQUAL_128(...)`: These are assertion macros used to verify the results of the assembly code execution. They compare the actual register values with expected values.
    * Register names like `s0`, `s1`, ..., `d0`, `d1`, ..., `q0`, `q1`: Standard ARM64 floating-point register names (single-precision, double-precision, and quad-precision).
    * Constants like `kFP32PositiveInfinity`, `kFP32NegativeInfinity`:  Represent special floating-point values.

3. **Infer Functionality of Individual Tests:** Based on the assembly instructions and the `CHECK_EQUAL` assertions, I can infer what each test case is verifying. For instance:
    * `TEST(frinta)`: Tests the `Frinta` (round to nearest, ties away from zero) floating-point rounding instruction. It sets up various floating-point input values and checks if `Frinta` produces the expected rounded results.
    * `TEST(frintm)`: Tests the `Frintm` (round towards negative infinity) instruction.
    * `TEST(frintn)`: Tests the `Frintn` (round to nearest, ties to even) instruction.
    * `TEST(frintp)`: Tests the `Frintp` (round towards positive infinity) instruction.
    * `TEST(frintz)`: Tests the `Frintz` (round towards zero) instruction.
    * `TEST(fcvt_ds)`: Tests the `Fcvt` instruction for converting single-precision floating-point to double-precision.
    * `TEST(fcvt_sd)`: Tests the `Fcvt` instruction for converting double-precision floating-point to single-precision, including various rounding scenarios and edge cases (overflow, underflow, NaNs).
    * `TEST(fcvtas)`, `TEST(fcvtau)`, `TEST(fcvtms)`, `TEST(fcvtmu)`, `TEST(fcvtn)`, `TEST(fcvtns)`, `TEST(fcvtnu)`: These test various `Fcvt` instructions that convert floating-point numbers to integers with different rounding modes and signed/unsigned interpretations.

4. **Address Specific Questions:** Now I can address the specific questions in the prompt:
    * **Functionality:** The primary function is to test the ARM64 assembler implementation within V8, specifically focusing on floating-point instructions for rounding and conversion.
    * **.tq Extension:** The code is C++, not Torque, so it wouldn't have a `.tq` extension.
    * **Relationship to JavaScript:**  These low-level assembler tests are indirectly related to JavaScript. V8 compiles JavaScript code into machine code, and these tests ensure the floating-point operations are handled correctly at the machine code level, impacting the accuracy and behavior of JavaScript numerical computations.
    * **JavaScript Example:** I can provide JavaScript examples that demonstrate the different rounding behaviors being tested (e.g., using `Math.round`, `Math.floor`, `Math.ceil`, or by performing operations that might lead to conversions between single and double precision).
    * **Code Logic Inference (Hypothetical):** For instructions like rounding, I can provide examples of input values and the expected rounded output based on the rounding mode. For conversions, I can show input and the expected converted value.
    * **Common Programming Errors:** I can discuss common errors related to floating-point arithmetic in JavaScript, such as precision issues, comparisons, and unexpected rounding.
    * **Part 10 of 15:**  Knowing this is part of a larger set, I can infer that the complete test suite covers a broader range of ARM64 assembler instructions.

5. **Synthesize and Summarize:** Finally, I synthesize the information gathered to provide a concise summary of the code's functionality, addressing all aspects of the prompt. I organize the information logically and provide clear explanations.

By following these steps, I can effectively analyze the C++ code snippet and provide a comprehensive answer to the user's request. The key is to leverage the file path, keywords, and code structure to infer the purpose and functionality of the code.
这是一个V8 JavaScript引擎的C++源代码文件，位于`v8/test/cctest/`目录下，专门用于测试 **ARM64架构** 的 **汇编器（Assembler）** 的功能。

**功能归纳:**

这个代码片段主要测试了ARM64架构下汇编器的以下浮点数相关的指令的功能：

1. **浮点数舍入指令 (Rounding Instructions):**
   - `Frinta` (Round to nearest, ties away from zero)
   - `Frintm` (Round towards negative infinity)
   - `Frintn` (Round to nearest, ties to even)
   - `Frintp` (Round towards positive infinity)
   - `Frintz` (Round towards zero)

2. **浮点数类型转换指令 (Floating-point Conversion Instructions):**
   - `Fcvt_ds` (Convert single-precision float to double-precision float)
   - `Fcvt_sd` (Convert double-precision float to single-precision float)
   - `Fcvtas` (Convert floating-point to signed integer, rounding to nearest, ties away from zero)
   - `Fcvtau` (Convert floating-point to unsigned integer, rounding to nearest, ties away from zero)
   - `Fcvtms` (Convert floating-point to signed integer, rounding towards negative infinity)
   - `Fcvtmu` (Convert floating-point to unsigned integer, rounding towards negative infinity)
   - `Fcvtn` (Convert double-precision float to single-precision float, narrowing)
   - `Fcvtns` (Convert floating-point to signed integer, narrowing)
   - `Fcvtnu` (Convert floating-point to unsigned integer, narrowing)

**关于文件类型:**

- 正如您所说，如果 `v8/test/cctest/test-assembler-arm64.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码文件。但由于它以 `.cc` 结尾，所以它是一个 **C++** 源代码文件。

**与 JavaScript 的关系 (间接):**

这个文件中的测试代码直接测试的是 V8 引擎中 ARM64 汇编器的实现。汇编器负责将 V8 的中间表示（如字节码或 TurboFan 生成的机器码）转换成实际的 ARM64 机器指令。

因此，这些测试确保了 V8 在 ARM64 架构上执行 JavaScript 代码时，与浮点数相关的操作（如算术运算、类型转换等）能够按照预期进行。

**JavaScript 举例说明 (与浮点数舍入相关):**

```javascript
// 对应 Frinta (Round to nearest, ties away from zero)
console.log(Math.round(1.5));   // 输出: 2
console.log(Math.round(-1.5));  // 输出: -2

// 对应 Frintm (Round towards negative infinity)
console.log(Math.floor(1.9));   // 输出: 1
console.log(Math.floor(-1.1));  // 输出: -2

// 对应 Frintn (Round to nearest, ties to even)
console.log(Math.round(2.5));   // 输出: 2
console.log(Math.round(3.5));   // 输出: 4

// 对应 Frintp (Round towards positive infinity)
console.log(Math.ceil(1.1));    // 输出: 2
console.log(Math.ceil(-1.9));   // 输出: -1

// 对应 Frintz (Round towards zero)
console.log(Math.trunc(1.9));   // 输出: 1
console.log(Math.trunc(-1.9));  // 输出: -1
```

**代码逻辑推理 (以 `TEST(frinta)` 为例):**

**假设输入:**

- 初始化一些单精度浮点数 (s16-s27) 和双精度浮点数 (d16-d27)，包含正负数、小数、无穷大、零等。

**代码逻辑:**

1. 使用 `__ Fmov` 指令将这些浮点数加载到 ARM64 寄存器中。
2. 使用 `__ Frinta` 指令对这些寄存器中的浮点数进行舍入操作，并将结果存储到目标寄存器 (s0-s11 和 d12-d23)。

**预期输出:**

- `CHECK_EQUAL_FP32` 和 `CHECK_EQUAL_FP64` 宏会断言目标寄存器中的值是否与预期舍入后的值相等。

例如，对于 `__ Frinta(s1, s17);`，输入 `s17` 的值为 `1.1`，预期输出 `s1` 的值为 `1.0` (因为 `Frinta` 是四舍五入到最接近的整数， ties away from zero)。

**用户常见的编程错误 (与浮点数转换相关):**

```javascript
// 错误示例 1: 精度丢失
let largeNumber = 9007199254740992; // 大于 Number.MAX_SAFE_INTEGER
let floatNumber = largeNumber;
console.log(largeNumber === floatNumber); // 输出: true (可能丢失精度)

// 错误示例 2: 浮点数比较
let a = 0.1 + 0.2;
let b = 0.3;
console.log(a === b); // 输出: false (浮点数精度问题)

// 错误示例 3: 未考虑舍入误差
let price = 10.55;
let quantity = 3;
let total = price * quantity;
console.log(total); // 输出: 31.650000000000002 (可能需要手动处理舍入)

// 错误示例 4: 假设整数到浮点数的转换总是精确的 (对于大整数不成立)
let bigInt = 9007199254740993n;
let num = Number(bigInt);
console.log(bigInt === BigInt(num)); // 输出: false
```

**第 10 部分，共 15 部分的功能:**

作为测试套件的第 10 部分，这个文件专注于测试 ARM64 架构汇编器中 **浮点数舍入和类型转换** 相关的指令。可以推断，其他部分可能涵盖了其他类型的 ARM64 指令，例如整数运算、内存访问、分支跳转等。整个测试套件的目标是全面验证 V8 引擎在 ARM64 架构上的汇编器实现的正确性，确保生成的机器码能够正确执行 JavaScript 代码。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
nta(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(3.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-3.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(3.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-3.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintm) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintm(s0, s16);
  __ Frintm(s1, s17);
  __ Frintm(s2, s18);
  __ Frintm(s3, s19);
  __ Frintm(s4, s20);
  __ Frintm(s5, s21);
  __ Frintm(s6, s22);
  __ Frintm(s7, s23);
  __ Frintm(s8, s24);
  __ Frintm(s9, s25);
  __ Frintm(s10, s26);
  __ Frintm(s11, s27);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintm(d12, d16);
  __ Frintm(d13, d17);
  __ Frintm(d14, d18);
  __ Frintm(d15, d19);
  __ Frintm(d16, d20);
  __ Frintm(d17, d21);
  __ Frintm(d18, d22);
  __ Frintm(d19, d23);
  __ Frintm(d20, d24);
  __ Frintm(d21, d25);
  __ Frintm(d22, d26);
  __ Frintm(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(1.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-3.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-1.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(1.0, d14);
  CHECK_EQUAL_FP64(1.0, d15);
  CHECK_EQUAL_FP64(2.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-3.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-1.0, d23);
}

TEST(frintn) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintn(s0, s16);
  __ Frintn(s1, s17);
  __ Frintn(s2, s18);
  __ Frintn(s3, s19);
  __ Frintn(s4, s20);
  __ Frintn(s5, s21);
  __ Frintn(s6, s22);
  __ Frintn(s7, s23);
  __ Frintn(s8, s24);
  __ Frintn(s9, s25);
  __ Frintn(s10, s26);
  __ Frintn(s11, s27);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintn(d12, d16);
  __ Frintn(d13, d17);
  __ Frintn(d14, d18);
  __ Frintn(d15, d19);
  __ Frintn(d16, d20);
  __ Frintn(d17, d21);
  __ Frintn(d18, d22);
  __ Frintn(d19, d23);
  __ Frintn(d20, d24);
  __ Frintn(d21, d25);
  __ Frintn(d22, d26);
  __ Frintn(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-2.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(2.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(-2.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintp) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, -0.2);

  __ Frintp(s0, s16);
  __ Frintp(s1, s17);
  __ Frintp(s2, s18);
  __ Frintp(s3, s19);
  __ Frintp(s4, s20);
  __ Frintp(s5, s21);
  __ Frintp(s6, s22);
  __ Frintp(s7, s23);
  __ Frintp(s8, s24);
  __ Frintp(s9, s25);
  __ Frintp(s10, s26);
  __ Frintp(s11, s27);

  __ Fmov(d16, -0.5);
  __ Fmov(d17, -0.8);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);
  __ Fmov(d27, -0.2);

  __ Frintp(d12, d16);
  __ Frintp(d13, d17);
  __ Frintp(d14, d18);
  __ Frintp(d15, d19);
  __ Frintp(d16, d20);
  __ Frintp(d17, d21);
  __ Frintp(d18, d22);
  __ Frintp(d19, d23);
  __ Frintp(d20, d24);
  __ Frintp(d21, d25);
  __ Frintp(d22, d26);
  __ Frintp(d23, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(2.0, s1);
  CHECK_EQUAL_FP32(2.0, s2);
  CHECK_EQUAL_FP32(2.0, s3);
  CHECK_EQUAL_FP32(3.0, s4);
  CHECK_EQUAL_FP32(-1.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP32(-0.0, s11);
  CHECK_EQUAL_FP64(-0.0, d12);
  CHECK_EQUAL_FP64(-0.0, d13);
  CHECK_EQUAL_FP64(2.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(3.0, d16);
  CHECK_EQUAL_FP64(-1.0, d17);
  CHECK_EQUAL_FP64(-2.0, d18);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d19);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d20);
  CHECK_EQUAL_FP64(0.0, d21);
  CHECK_EQUAL_FP64(-0.0, d22);
  CHECK_EQUAL_FP64(-0.0, d23);
}

TEST(frintz) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);

  __ Frintz(s0, s16);
  __ Frintz(s1, s17);
  __ Frintz(s2, s18);
  __ Frintz(s3, s19);
  __ Frintz(s4, s20);
  __ Frintz(s5, s21);
  __ Frintz(s6, s22);
  __ Frintz(s7, s23);
  __ Frintz(s8, s24);
  __ Frintz(s9, s25);
  __ Frintz(s10, s26);

  __ Fmov(d16, 1.0);
  __ Fmov(d17, 1.1);
  __ Fmov(d18, 1.5);
  __ Fmov(d19, 1.9);
  __ Fmov(d20, 2.5);
  __ Fmov(d21, -1.5);
  __ Fmov(d22, -2.5);
  __ Fmov(d23, kFP32PositiveInfinity);
  __ Fmov(d24, kFP32NegativeInfinity);
  __ Fmov(d25, 0.0);
  __ Fmov(d26, -0.0);

  __ Frintz(d11, d16);
  __ Frintz(d12, d17);
  __ Frintz(d13, d18);
  __ Frintz(d14, d19);
  __ Frintz(d15, d20);
  __ Frintz(d16, d21);
  __ Frintz(d17, d22);
  __ Frintz(d18, d23);
  __ Frintz(d19, d24);
  __ Frintz(d20, d25);
  __ Frintz(d21, d26);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(1.0, s3);
  CHECK_EQUAL_FP32(2.0, s4);
  CHECK_EQUAL_FP32(-1.0, s5);
  CHECK_EQUAL_FP32(-2.0, s6);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s7);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s8);
  CHECK_EQUAL_FP32(0.0, s9);
  CHECK_EQUAL_FP32(-0.0, s10);
  CHECK_EQUAL_FP64(1.0, d11);
  CHECK_EQUAL_FP64(1.0, d12);
  CHECK_EQUAL_FP64(1.0, d13);
  CHECK_EQUAL_FP64(1.0, d14);
  CHECK_EQUAL_FP64(2.0, d15);
  CHECK_EQUAL_FP64(-1.0, d16);
  CHECK_EQUAL_FP64(-2.0, d17);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d18);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d19);
  CHECK_EQUAL_FP64(0.0, d20);
  CHECK_EQUAL_FP64(-0.0, d21);
}

TEST(fcvt_ds) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 1.5);
  __ Fmov(s19, 1.9);
  __ Fmov(s20, 2.5);
  __ Fmov(s21, -1.5);
  __ Fmov(s22, -2.5);
  __ Fmov(s23, kFP32PositiveInfinity);
  __ Fmov(s24, kFP32NegativeInfinity);
  __ Fmov(s25, 0.0);
  __ Fmov(s26, -0.0);
  __ Fmov(s27, FLT_MAX);
  __ Fmov(s28, FLT_MIN);
  __ Fmov(s29, base::bit_cast<float>(0x7FC12345));  // Quiet NaN.
  __ Fmov(s30, base::bit_cast<float>(0x7F812345));  // Signalling NaN.

  __ Fcvt(d0, s16);
  __ Fcvt(d1, s17);
  __ Fcvt(d2, s18);
  __ Fcvt(d3, s19);
  __ Fcvt(d4, s20);
  __ Fcvt(d5, s21);
  __ Fcvt(d6, s22);
  __ Fcvt(d7, s23);
  __ Fcvt(d8, s24);
  __ Fcvt(d9, s25);
  __ Fcvt(d10, s26);
  __ Fcvt(d11, s27);
  __ Fcvt(d12, s28);
  __ Fcvt(d13, s29);
  __ Fcvt(d14, s30);
  END();

  RUN();

  CHECK_EQUAL_FP64(1.0f, d0);
  CHECK_EQUAL_FP64(1.1f, d1);
  CHECK_EQUAL_FP64(1.5f, d2);
  CHECK_EQUAL_FP64(1.9f, d3);
  CHECK_EQUAL_FP64(2.5f, d4);
  CHECK_EQUAL_FP64(-1.5f, d5);
  CHECK_EQUAL_FP64(-2.5f, d6);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d7);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d8);
  CHECK_EQUAL_FP64(0.0f, d9);
  CHECK_EQUAL_FP64(-0.0f, d10);
  CHECK_EQUAL_FP64(FLT_MAX, d11);
  CHECK_EQUAL_FP64(FLT_MIN, d12);

  // Check that the NaN payload is preserved according to ARM64 conversion
  // rules:
  //  - The sign bit is preserved.
  //  - The top bit of the mantissa is forced to 1 (making it a quiet NaN).
  //  - The remaining mantissa bits are copied until they run out.
  //  - The low-order bits that haven't already been assigned are set to 0.
  CHECK_EQUAL_FP64(base::bit_cast<double>(0x7FF82468A0000000), d13);
  CHECK_EQUAL_FP64(base::bit_cast<double>(0x7FF82468A0000000), d14);
}

TEST(fcvt_sd) {
  INIT_V8();
  // There are a huge number of corner-cases to check, so this test iterates
  // through a list. The list is then negated and checked again (since the sign
  // is irrelevant in ties-to-even rounding), so the list shouldn't include any
  // negative values.
  //
  // Note that this test only checks ties-to-even rounding, because that is all
  // that the simulator supports.
  struct {
    double in;
    float expected;
  } test[] = {
      // Check some simple conversions.
      {0.0, 0.0f},
      {1.0, 1.0f},
      {1.5, 1.5f},
      {2.0, 2.0f},
      {FLT_MAX, FLT_MAX},
      //  - The smallest normalized float.
      {pow(2.0, -126), powf(2, -126)},
      //  - Normal floats that need (ties-to-even) rounding.
      //    For normalized numbers:
      //         bit 29 (0x0000000020000000) is the lowest-order bit which will
      //                                     fit in the float's mantissa.
      {base::bit_cast<double>(0x3FF0000000000000),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000000000001),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000010000000),
       base::bit_cast<float>(0x3F800000)},
      {base::bit_cast<double>(0x3FF0000010000001),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000020000000),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000020000001),
       base::bit_cast<float>(0x3F800001)},
      {base::bit_cast<double>(0x3FF0000030000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000030000001),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000040000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000040000001),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000050000000),
       base::bit_cast<float>(0x3F800002)},
      {base::bit_cast<double>(0x3FF0000050000001),
       base::bit_cast<float>(0x3F800003)},
      {base::bit_cast<double>(0x3FF0000060000000),
       base::bit_cast<float>(0x3F800003)},
      //  - A mantissa that overflows into the exponent during rounding.
      {base::bit_cast<double>(0x3FEFFFFFF0000000),
       base::bit_cast<float>(0x3F800000)},
      //  - The largest double that rounds to a normal float.
      {base::bit_cast<double>(0x47EFFFFFEFFFFFFF),
       base::bit_cast<float>(0x7F7FFFFF)},

      // Doubles that are too big for a float.
      {kFP64PositiveInfinity, kFP32PositiveInfinity},
      {DBL_MAX, kFP32PositiveInfinity},
      //  - The smallest exponent that's too big for a float.
      {pow(2.0, 128), kFP32PositiveInfinity},
      //  - This exponent is in range, but the value rounds to infinity.
      {base::bit_cast<double>(0x47EFFFFFF0000000), kFP32PositiveInfinity},

      // Doubles that are too small for a float.
      //  - The smallest (subnormal) double.
      {DBL_MIN, 0.0},
      //  - The largest double which is too small for a subnormal float.
      {base::bit_cast<double>(0x3690000000000000),
       base::bit_cast<float>(0x00000000)},

      // Normal doubles that become subnormal floats.
      //  - The largest subnormal float.
      {base::bit_cast<double>(0x380FFFFFC0000000),
       base::bit_cast<float>(0x007FFFFF)},
      //  - The smallest subnormal float.
      {base::bit_cast<double>(0x36A0000000000000),
       base::bit_cast<float>(0x00000001)},
      //  - Subnormal floats that need (ties-to-even) rounding.
      //    For these subnormals:
      //         bit 34 (0x0000000400000000) is the lowest-order bit which will
      //                                     fit in the float's mantissa.
      {base::bit_cast<double>(0x37C159E000000000),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E000000001),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E200000000),
       base::bit_cast<float>(0x00045678)},
      {base::bit_cast<double>(0x37C159E200000001),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E400000000),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E400000001),
       base::bit_cast<float>(0x00045679)},
      {base::bit_cast<double>(0x37C159E600000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E600000001),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E800000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159E800000001),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159EA00000000),
       base::bit_cast<float>(0x0004567A)},
      {base::bit_cast<double>(0x37C159EA00000001),
       base::bit_cast<float>(0x0004567B)},
      {base::bit_cast<double>(0x37C159EC00000000),
       base::bit_cast<float>(0x0004567B)},
      //  - The smallest double which rounds up to become a subnormal float.
      {base::bit_cast<double>(0x3690000000000001),
       base::bit_cast<float>(0x00000001)},

      // Check NaN payload preservation.
      {base::bit_cast<double>(0x7FF82468A0000000),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF82468BFFFFFFF),
       base::bit_cast<float>(0x7FC12345)},
      //  - Signalling NaNs become quiet NaNs.
      {base::bit_cast<double>(0x7FF02468A0000000),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF02468BFFFFFFF),
       base::bit_cast<float>(0x7FC12345)},
      {base::bit_cast<double>(0x7FF000001FFFFFFF),
       base::bit_cast<float>(0x7FC00000)},
  };
  int count = sizeof(test) / sizeof(test[0]);

  for (int i = 0; i < count; i++) {
    double in = test[i].in;
    float expected = test[i].expected;

    // We only expect positive input.
    CHECK_EQ(std::signbit(in), 0);
    CHECK_EQ(std::signbit(expected), 0);

    SETUP();
    START();

    __ Fmov(d10, in);
    __ Fcvt(s20, d10);

    __ Fmov(d11, -in);
    __ Fcvt(s21, d11);

    END();
    RUN();
    CHECK_EQUAL_FP32(expected, s20);
    CHECK_EQUAL_FP32(-expected, s21);
  }
}

TEST(fcvtas) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 2.5);
  __ Fmov(s3, -2.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 2.5);
  __ Fmov(d11, -2.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 2.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -2.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 2.5);
  __ Fmov(d26, -2.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtas(w0, s0);
  __ Fcvtas(w1, s1);
  __ Fcvtas(w2, s2);
  __ Fcvtas(w3, s3);
  __ Fcvtas(w4, s4);
  __ Fcvtas(w5, s5);
  __ Fcvtas(w6, s6);
  __ Fcvtas(w7, s7);
  __ Fcvtas(w8, d8);
  __ Fcvtas(w9, d9);
  __ Fcvtas(w10, d10);
  __ Fcvtas(w11, d11);
  __ Fcvtas(w12, d12);
  __ Fcvtas(w13, d13);
  __ Fcvtas(w14, d14);
  __ Fcvtas(w15, d15);
  __ Fcvtas(x17, s17);
  __ Fcvtas(x19, s19);
  __ Fcvtas(x20, s20);
  __ Fcvtas(x21, s21);
  __ Fcvtas(x22, s22);
  __ Fcvtas(x23, s23);
  __ Fcvtas(x24, d24);
  __ Fcvtas(x25, d25);
  __ Fcvtas(x26, d26);
  __ Fcvtas(x27, d27);
  __ Fcvtas(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtas(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtas(x29, d29);
  __ Fcvtas(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(3, x2);
  CHECK_EQUAL_64(0xFFFFFFFD, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(0xFFFFFFFD, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(3, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFDUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(3, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFDUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtau) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 2.5);
  __ Fmov(s3, -2.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0xFFFFFF00);  // Largest float < UINT32_MAX.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 2.5);
  __ Fmov(d11, -2.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, 0xFFFFFFFE);
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s18, 2.5);
  __ Fmov(s19, -2.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0xFFFFFF0000000000UL);  // Largest float < UINT64_MAX.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 2.5);
  __ Fmov(d26, -2.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0xFFFFFFFFFFFFF800UL);  // Largest double < UINT64_MAX.
  __ Fmov(s30, 0x100000000UL);

  __ Fcvtau(w0, s0);
  __ Fcvtau(w1, s1);
  __ Fcvtau(w2, s2);
  __ Fcvtau(w3, s3);
  __ Fcvtau(w4, s4);
  __ Fcvtau(w5, s5);
  __ Fcvtau(w6, s6);
  __ Fcvtau(w8, d8);
  __ Fcvtau(w9, d9);
  __ Fcvtau(w10, d10);
  __ Fcvtau(w11, d11);
  __ Fcvtau(w12, d12);
  __ Fcvtau(w13, d13);
  __ Fcvtau(w14, d14);
  __ Fcvtau(w15, d15);
  __ Fcvtau(x16, s16);
  __ Fcvtau(x17, s17);
  __ Fcvtau(x7, s18);
  __ Fcvtau(x19, s19);
  __ Fcvtau(x20, s20);
  __ Fcvtau(x21, s21);
  __ Fcvtau(x22, s22);
  __ Fcvtau(x24, d24);
  __ Fcvtau(x25, d25);
  __ Fcvtau(x26, d26);
  __ Fcvtau(x27, d27);
  __ Fcvtau(x28, d28);
  __ Fcvtau(x29, d29);
  __ Fcvtau(w30, s30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(3, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(0xFFFFFFFF, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0xFFFFFF00, x6);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0xFFFFFFFF, x12);
  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(0xFFFFFFFE, x14);
  CHECK_EQUAL_64(1, x16);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(3, x7);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0, x21);
  CHECK_EQUAL_64(0xFFFFFF0000000000UL, x22);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(3, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0, x28);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFF800UL, x29);
  CHECK_EQUAL_64(0xFFFFFFFF, x30);
}

TEST(fcvtms) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtms(w0, s0);
  __ Fcvtms(w1, s1);
  __ Fcvtms(w2, s2);
  __ Fcvtms(w3, s3);
  __ Fcvtms(w4, s4);
  __ Fcvtms(w5, s5);
  __ Fcvtms(w6, s6);
  __ Fcvtms(w7, s7);
  __ Fcvtms(w8, d8);
  __ Fcvtms(w9, d9);
  __ Fcvtms(w10, d10);
  __ Fcvtms(w11, d11);
  __ Fcvtms(w12, d12);
  __ Fcvtms(w13, d13);
  __ Fcvtms(w14, d14);
  __ Fcvtms(w15, d15);
  __ Fcvtms(x17, s17);
  __ Fcvtms(x19, s19);
  __ Fcvtms(x20, s20);
  __ Fcvtms(x21, s21);
  __ Fcvtms(x22, s22);
  __ Fcvtms(x23, s23);
  __ Fcvtms(x24, d24);
  __ Fcvtms(x25, d25);
  __ Fcvtms(x26, d26);
  __ Fcvtms(x27, d27);
  __ Fcvtms(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtms(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtms(x29, d29);
  __ Fcvtms(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0xFFFFFFFE, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(1, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(1, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtmu) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtmu(w0, s0);
  __ Fcvtmu(w1, s1);
  __ Fcvtmu(w2, s2);
  __ Fcvtmu(w3, s3);
  __ Fcvtmu(w4, s4);
  __ Fcvtmu(w5, s5);
  __ Fcvtmu(w6, s6);
  __ Fcvtmu(w7, s7);
  __ Fcvtmu(w8, d8);
  __ Fcvtmu(w9, d9);
  __ Fcvtmu(w10, d10);
  __ Fcvtmu(w11, d11);
  __ Fcvtmu(w12, d12);
  __ Fcvtmu(w13, d13);
  __ Fcvtmu(w14, d14);
  __ Fcvtmu(w15, d15);
  __ Fcvtmu(x17, s17);
  __ Fcvtmu(x19, s19);
  __ Fcvtmu(x20, s20);
  __ Fcvtmu(x21, s21);
  __ Fcvtmu(x22, s22);
  __ Fcvtmu(x23, s23);
  __ Fcvtmu(x24, d24);
  __ Fcvtmu(x25, d25);
  __ Fcvtmu(x26, d26);
  __ Fcvtmu(x27, d27);
  __ Fcvtmu(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtmu(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtmu(x29, d29);
  __ Fcvtmu(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(0xFFFFFFFF, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0xFFFFFFFF, x12);
  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x0, x15);
  CHECK_EQUAL_64(1, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0x0UL, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x0UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x0UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(1, x25);
  CHECK_EQUAL_64(0x0UL, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x0UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x0UL, x30);
}

TEST(fcvtn) {
  INIT_V8();
  SETUP();
  START();

  double src[2] = {1.0f, 1.0f};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  __ Mov(x0, src_base);
  __ Ldr(q0, MemOperand(x0, 0));

  __ Fcvtn(q0.V2S(), q0.V2D());

  END();
  RUN();

  // Ensure top half is cleared.
  CHECK_EQUAL_128(0, 0x3f800000'3f800000, q0);
}

TEST(fcvtns) {
  INIT_V8();
  SETUP();

  int64_t scratch = 0;
  uintptr_t scratch_base = reinterpret_cast<uintptr_t>(&scratch);

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0x7FFFFF80);  // Largest float < INT32_MAX.
  __ Fneg(s7, s6);          // Smallest float > INT32_MIN.
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, kWMaxInt - 1);
  __ Fmov(d15, kWMinInt + 1);
  __ Fmov(s16, 1.5);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0x7FFFFF8000000000UL);   // Largest float < INT64_MAX.
  __ Fneg(s23, s22);                    // Smallest float > INT64_MIN.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0x7FFFFFFFFFFFFC00UL);   // Largest double < INT64_MAX.
  __ Fneg(d30, d29);                    // Smallest double > INT64_MIN.

  __ Fcvtns(w0, s0);
  __ Fcvtns(w1, s1);
  __ Fcvtns(w2, s2);
  __ Fcvtns(w3, s3);
  __ Fcvtns(w4, s4);
  __ Fcvtns(w5, s5);
  __ Fcvtns(w6, s6);
  __ Fcvtns(w7, s7);
  __ Fcvtns(w8, d8);
  __ Fcvtns(w9, d9);
  __ Fcvtns(w10, d10);
  __ Fcvtns(w11, d11);
  __ Fcvtns(w12, d12);
  __ Fcvtns(w13, d13);
  __ Fcvtns(w14, d14);
  __ Fcvtns(w15, d15);
  __ Fcvtns(x17, s17);
  __ Fcvtns(x19, s19);
  __ Fcvtns(x20, s20);
  __ Fcvtns(x21, s21);
  __ Fcvtns(x22, s22);
  __ Fcvtns(x23, s23);
  __ Fcvtns(x24, d24);
  __ Fcvtns(x25, d25);
  __ Fcvtns(x26, d26);
  __ Fcvtns(x27, d27);
//  __ Fcvtns(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtns(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtns(x29, d29);
  __ Fcvtns(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(2, x2);
  CHECK_EQUAL_64(0xFFFFFFFE, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(2, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(2, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(2, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  //  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

TEST(fcvtnu) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s0, 1.0);
  __ Fmov(s1, 1.1);
  __ Fmov(s2, 1.5);
  __ Fmov(s3, -1.5);
  __ Fmov(s4, kFP32PositiveInfinity);
  __ Fmov(s5, kFP32NegativeInfinity);
  __ Fmov(s6, 0xFFFFFF00);  // Largest float < UINT32_MAX.
  __ Fmov(s7, 1.5);
  __ Fmov(d8, 1.0);
  __ Fmov(d9, 1.1);
  __ Fmov(d10, 1.5);
  __ Fmov(d11, -1.5);
  __ Fmov(d12, kFP64PositiveInfinity);
  __ Fmov(d13, kFP64NegativeInfinity);
  __ Fmov(d14, 0xFFFFFFFE);
  __ Fmov(s16, 1.0);
  __ Fmov(s17, 1.1);
  __ Fmov(s19, -1.5);
  __ Fmov(s20, kFP32PositiveInfinity);
  __ Fmov(s21, kFP32NegativeInfinity);
  __ Fmov(s22, 0xFFFFFF0000000000UL);  // Largest float < UINT64_MAX.
  __ Fmov(d24, 1.1);
  __ Fmov(d25, 1.5);
  __ Fmov(d26, -1.5);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0xFFFFFFFFFFFFF800UL);  // Largest double < UINT64_MAX.
  __ Fmov(s30, 0x100000000UL);

  __ Fcvtnu(w0, s0);
  __ Fcvtnu(w1, s1);
  __ Fcvtnu(w2, s2);
  __ Fcvtnu(w3, s3);
  __ Fcvtnu(w4, s4);
  __ Fcvtnu(w5, s5);
  __ Fcvtnu(w6, s6);
  __ Fcvtnu(x7, s7);
  __ Fcvtnu(w8, d8);
  __ Fcvtnu(w9, d9);
  _
```