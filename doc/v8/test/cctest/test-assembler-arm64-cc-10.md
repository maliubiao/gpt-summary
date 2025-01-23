Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The primary goal is to analyze the provided ARM64 assembly code snippet from a V8 test file (`test-assembler-arm64.cc`) and describe its functionality. The request also includes specific constraints related to file extensions, JavaScript relevance, code logic, common errors, and summarization.

2. **Identify the File Type and Purpose:** The filename `test-assembler-arm64.cc` strongly suggests this is a C++ test file for the ARM64 assembler within the V8 JavaScript engine. The `.cc` extension confirms it's C++. The presence of `TEST()` macros indicates it's using a testing framework (likely Google Test, commonly used in Chromium/V8). The `assembler-arm64` part clearly points to testing ARM64 assembly code generation.

3. **Analyze the Code Snippet:** I'll break down the code into logical blocks:

    * **`Fcvtnu` Tests:**  The first `TEST(fcvtnu)` block uses `__ Fmov` to load floating-point values into SIMD registers (s and d registers) and then uses `__ Fcvtnu` to convert these floating-point values to unsigned integers and store them in general-purpose registers (w and x registers). The `CHECK_EQUAL_64` macros verify the results.

    * **`Fcvtzs` Tests:** The `TEST(fcvtzs)` block is similar, but uses `__ Fcvtzs` to convert floating-point values to signed integers. It also includes a section using `__ Mov` and `__ Str` to save results to memory (indicated by `scratch` and `scratch_base`).

    * **`FjcvtzsHelper` and `fjcvtzs`:** This section introduces a helper function `FjcvtzsHelper` and a test case `TEST(fjcvtzs)`. The helper function takes a double-precision floating-point value, converts it to an integer using `__ Fjcvtzs`, and checks the result and the Z flag. The `fjcvtzs` test case calls this helper with various floating-point inputs, including normal numbers, infinity, NaNs, and subnormals, both positive and negative.

    * **`Fcvtzu` Tests:**  The `TEST(fcvtzu)` block mirrors the `fcvtnu` test but uses `__ Fcvtzu` for converting to unsigned integers.

    * **`TestUScvtfHelper` and `scvtf_ucvtf_double`:** This section tests the `__ Scvtf` (signed integer to floating-point) and `__ Ucvtf` (unsigned integer to floating-point) instructions for converting to double-precision floats. It tests with various integer inputs and different values for the `fbits` parameter, which controls the number of fractional bits.

    * **`TestUScvtf32Helper` and `scvtf_ucvtf_float`:** Similar to the double-precision test, but tests conversions to single-precision floats.

    * **System Register Tests (`system_mrs`, `system_msr`, `system_pauth_b`, `system`):** These tests focus on reading and writing system registers using `__ Mrs` and `__ Msr`, specifically testing NZCV flags and FPCR. `system_pauth_b` tests pointer authentication instructions. The `system` test checks basic instruction execution.

    * **Zero Destination Tests (`zero_dest`, `zero_dest_setflags`):** These tests examine instructions where the destination register is the zero register (`xzr`). They verify that these instructions behave as NOPs in these specific forms, preventing accidental writes to the stack pointer.

4. **Address Specific Request Points:**

    * **Functionality:** I'll summarize the functionality of each test case based on the instructions used and the assertions made.
    * **`.tq` Extension:** I can definitively state that the file is `.cc` and not `.tq`, so it's a C++ test, not a Torque file.
    * **JavaScript Relation:** Since this is an assembler test, the direct relation to specific JavaScript code is at the assembly level. I'll provide an example of a JavaScript operation that might involve floating-point to integer conversion, which would potentially use the tested assembly instructions.
    * **Code Logic and I/O:** For the `Fcvtnu`, `Fcvtzs`, `Fcvtzu`, `scvtf`, and `ucvtf` tests, I can identify the input (floating-point or integer values) and the expected output (integer or floating-point values) based on the `CHECK_EQUAL` macros. For `fjcvtzs`, I can infer the expected output based on the tested floating-point values and the nature of the conversion.
    * **Common Programming Errors:** The zero destination tests highlight a potential error: accidentally using instructions that could modify the stack pointer unexpectedly if the zero register wasn't handled correctly. I'll provide a concrete example.
    * **Part 11 of 15:** I'll acknowledge this and ensure the summary reflects the code provided in this specific part.

5. **Structure the Answer:** I'll organize the information clearly, addressing each point of the request systematically. I'll use headings and bullet points for better readability.

6. **Refine and Review:** I'll reread the generated answer to ensure accuracy, completeness, and clarity, and make sure all parts of the prompt are addressed. I'll double-check the code analysis and the JavaScript example.

By following this systematic process, I can generate a comprehensive and accurate answer that addresses all aspects of the request. The key is to understand the purpose of the code, analyze its components, and connect it to the broader context of V8 and JavaScript execution.
This is the 11th part of a 15-part analysis of the V8 source code file `v8/test/cctest/test-assembler-arm64.cc`.

**Overall Functionality of `v8/test/cctest/test-assembler-arm64.cc`:**

This C++ file contains unit tests for the ARM64 assembler in the V8 JavaScript engine. It tests the correct generation and execution of various ARM64 assembly instructions. Each `TEST()` block focuses on a specific set of instructions or a particular aspect of the assembler.

**Functionality of the Provided Snippet (Part 11):**

This specific part of the file focuses on testing **floating-point to integer conversion instructions** and **integer to floating-point conversion instructions** on the ARM64 architecture. It uses the V8 assembler (`__`) to generate sequences of these instructions and then executes them, verifying the results against expected values.

Here's a breakdown of the tested instructions and their functionalities:

* **`Fcvtnu` (Floating-point Convert to Unsigned):**  Converts floating-point numbers (single-precision 's' and double-precision 'd') to unsigned integers (32-bit 'w' and 64-bit 'x'). It truncates towards zero.
* **`Fcvtzs` (Floating-point Convert to Signed, rounding towards Zero):** Converts floating-point numbers to signed integers, rounding towards zero.
* **`Fjcvtzs` (Floating-point Javascript Convert to Signed, rounding towards Zero):**  A variant of `Fcvtzs` specifically for JavaScript semantics. It sets the Z flag under certain conditions (when the result is zero).
* **`Fcvtzu` (Floating-point Convert to Unsigned, rounding towards Zero):** Converts floating-point numbers to unsigned integers, rounding towards zero.
* **`Scvtf` (Signed Convert to Floating-point):** Converts signed integers to floating-point numbers (single-precision 's' and double-precision 'd').
* **`Ucvtf` (Unsigned Convert to Floating-point):** Converts unsigned integers to floating-point numbers.
* **System Register Access (`Mrs`, `Msr`):**
    * `Mrs` (Move from System Register): Reads the value of a system register (like `NZCV` for flags, `FPCR` for floating-point control register).
    * `Msr` (Move to System Register): Writes a value to a system register.
* **Pointer Authentication (`Pacib1716`, `Pacibsp`, `Autib1716`, `Autibsp`):** Tests instructions for generating and authenticating pointer authentication codes (PACs) to enhance security.
* **Generic System Instruction (`Csdb`):**  Cache synchronization barrier.
* **Zero Register Behavior:** Tests that operations with the zero register (`xzr`) as the destination do not modify other registers (acting as NOPs in some forms).

**If `v8/test/cctest/test-assembler-arm64.cc` ended with `.tq`:**

Then it would be a V8 Torque source file. Torque is a domain-specific language used within V8 for generating optimized code, often for built-in functions. This file, however, ends in `.cc`, indicating it's a standard C++ source file.

**Relationship to JavaScript Functionality (with JavaScript Example):**

The floating-point to integer conversion instructions tested here are directly related to how JavaScript handles operations that convert numbers to integers. For example, the `Math.trunc()`, `Math.floor()`, `Math.ceil()`, and bitwise operators like `| 0` internally rely on these kinds of conversions.

**JavaScript Example:**

```javascript
let floatValue = 3.7;
let unsignedIntValue = Math.trunc(floatValue); // Internally might use FCVTNU
console.log(unsignedIntValue); // Output: 3

let negativeFloat = -2.3;
let signedIntValue = negativeFloat | 0; // Internally might use FCVTZS
console.log(signedIntValue); // Output: -2
```

The integer to floating-point conversions are used when JavaScript needs to represent integer values as floating-point numbers, which is common due to JavaScript's single number type (double-precision floating-point).

**JavaScript Example:**

```javascript
let integerValue = 10;
let floatRepresentation = integerValue / 1; // Implicit conversion to float
console.log(floatRepresentation); // Output: 10
```

**Code Logic Inference (with Hypothetical Input and Output for `Fcvtnu`):**

**Assumption:** We focus on the `TEST(fcvtnu)` block.

**Hypothetical Input:**

* `d0` (double): 1.0
* `d1` (double): 1.1
* `d2` (double): 2.0
* `d3` (double): -1.5
* `d4` (double): Infinity
* `d5` (double): -Infinity
* `d6` (double): A large positive number
* `d7` (double): A large negative number
* `s8` (float): 1.0
* ... and so on for all the `Fmov` instructions.

**Expected Output (based on the `CHECK_EQUAL_64` calls):**

* `x0` (result of `Fcvtnu(w0, s0)`): 1
* `x1` (result of `Fcvtnu(w1, d1)`): 1
* `x2` (result of `Fcvtnu(w2, d2)`): 2
* `x3` (result of `Fcvtnu(w3, d3)`): 0  (Negative numbers convert to 0 for unsigned)
* `x4` (result of `Fcvtnu(w4, s4)`): 0xFFFFFFFF (Infinity converts to the maximum unsigned 32-bit integer)
* `x5` (result of `Fcvtnu(w5, s5)`): 0 (Negative infinity converts to 0)
* `x6` (result of `Fcvtnu(w6, d6)` - assuming it's slightly less than 2^24):  A large unsigned 32-bit value.
* ... and so on, matching the `CHECK_EQUAL_64` values.

**Common Programming Errors (Related to Floating-Point to Integer Conversion):**

1. **Assuming Truncation for Negative Numbers with Unsigned Conversion:** Programmers might incorrectly assume that converting a negative floating-point number to an unsigned integer will somehow preserve its magnitude or sign. As seen with `Fcvtnu`, negative numbers typically become zero or very large positive numbers when converted to unsigned integers.

   ```javascript
   let negativeFloat = -3.7;
   let unsignedInt = Math.trunc(negativeFloat); // -3
   // If you were to manually implement something similar expecting a positive result:
   // This is where the misunderstanding of unsigned conversion comes in.
   ```

2. **Ignoring Potential Loss of Precision:** When converting large floating-point numbers to integers, there might be a loss of precision if the floating-point number's magnitude exceeds the maximum value representable by the integer type.

   ```javascript
   let largeFloat = 9007199254740992; // Larger than the maximum safe integer in JavaScript
   let intValue = Math.trunc(largeFloat);
   console.log(intValue); // Output: 9007199254740992 (might be rounded or truncated depending on the exact value)
   ```

3. **Incorrect Rounding Assumptions:**  Different conversion instructions and methods use different rounding modes (truncation, rounding to nearest, etc.). Programmers need to be aware of which rounding behavior is being applied to avoid unexpected results.

**Summary of Functionality (Part 11):**

This section of `v8/test/cctest/test-assembler-arm64.cc` thoroughly tests the functionality of ARM64 instructions related to:

* **Converting floating-point numbers to both signed and unsigned integers, with and without specific JavaScript semantics.** This includes testing various input values like positive and negative numbers, infinity, and specific bit patterns.
* **Converting signed and unsigned integers to floating-point numbers (single and double precision), including variations with the `fbits` parameter for controlling fractional bits.**
* **Reading and writing system registers, specifically focusing on flag manipulation and the floating-point control register.**
* **Testing pointer authentication instructions for security.**
* **Verifying the behavior of instructions with the zero register as the destination.**

Essentially, this part ensures the ARM64 assembler in V8 correctly generates code for these crucial number conversion and system manipulation instructions, which are fundamental for JavaScript's runtime behavior.

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
_ Fcvtnu(w10, d10);
  __ Fcvtnu(w11, d11);
  __ Fcvtnu(w12, d12);
  __ Fcvtnu(w13, d13);
  __ Fcvtnu(w14, d14);
  __ Fcvtnu(w15, d15);
  __ Fcvtnu(x16, s16);
  __ Fcvtnu(x17, s17);
  __ Fcvtnu(x19, s19);
  __ Fcvtnu(x20, s20);
  __ Fcvtnu(x21, s21);
  __ Fcvtnu(x22, s22);
  __ Fcvtnu(x24, d24);
  __ Fcvtnu(x25, d25);
  __ Fcvtnu(x26, d26);
  __ Fcvtnu(x27, d27);
//  __ Fcvtnu(x28, d28);
  __ Fcvtnu(x29, d29);
  __ Fcvtnu(w30, s30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(2, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(0xFFFFFFFF, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0xFFFFFF00, x6);
  CHECK_EQUAL_64(2, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(2, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0xFFFFFFFF, x12);
  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(0xFFFFFFFE, x14);
  CHECK_EQUAL_64(1, x16);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0, x21);
  CHECK_EQUAL_64(0xFFFFFF0000000000UL, x22);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(2, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x27);
  //  CHECK_EQUAL_64(0, x28);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFF800UL, x29);
  CHECK_EQUAL_64(0xFFFFFFFF, x30);
}

TEST(fcvtzs) {
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

  __ Fcvtzs(w0, s0);
  __ Fcvtzs(w1, s1);
  __ Fcvtzs(w2, s2);
  __ Fcvtzs(w3, s3);
  __ Fcvtzs(w4, s4);
  __ Fcvtzs(w5, s5);
  __ Fcvtzs(w6, s6);
  __ Fcvtzs(w7, s7);
  __ Fcvtzs(w8, d8);
  __ Fcvtzs(w9, d9);
  __ Fcvtzs(w10, d10);
  __ Fcvtzs(w11, d11);
  __ Fcvtzs(w12, d12);
  __ Fcvtzs(w13, d13);
  __ Fcvtzs(w14, d14);
  __ Fcvtzs(w15, d15);
  __ Fcvtzs(x17, s17);
  __ Fcvtzs(x19, s19);
  __ Fcvtzs(x20, s20);
  __ Fcvtzs(x21, s21);
  __ Fcvtzs(x22, s22);
  __ Fcvtzs(x23, s23);
  __ Fcvtzs(x24, d24);
  __ Fcvtzs(x25, d25);
  __ Fcvtzs(x26, d26);
  __ Fcvtzs(x27, d27);
  __ Fcvtzs(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtmu(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtzs(x29, d29);
  __ Fcvtzs(x30, d30);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(0x7FFFFFFF, x4);
  CHECK_EQUAL_64(0x80000000, x5);
  CHECK_EQUAL_64(0x7FFFFF80, x6);
  CHECK_EQUAL_64(0x80000080, x7);
  CHECK_EQUAL_64(1, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0xFFFFFFFF, x11);
  CHECK_EQUAL_64(0x7FFFFFFF, x12);
  CHECK_EQUAL_64(0x80000000, x13);
  CHECK_EQUAL_64(0x7FFFFFFE, x14);
  CHECK_EQUAL_64(0x80000001, x15);
  CHECK_EQUAL_64(1, scratch);
  CHECK_EQUAL_64(1, x17);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x19);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x20);
  CHECK_EQUAL_64(0x8000000000000000UL, x21);
  CHECK_EQUAL_64(0x7FFFFF8000000000UL, x22);
  CHECK_EQUAL_64(0x8000008000000000UL, x23);
  CHECK_EQUAL_64(1, x24);
  CHECK_EQUAL_64(1, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x26);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x27);
  CHECK_EQUAL_64(0x8000000000000000UL, x28);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFC00UL, x29);
  CHECK_EQUAL_64(0x8000000000000400UL, x30);
}

static void FjcvtzsHelper(uint64_t value, uint64_t expected,
                          uint32_t expected_z) {
  SETUP();
  START();
  __ Fmov(d0, base::bit_cast<double>(value));
  __ Fjcvtzs(w0, d0);
  __ Mrs(x1, NZCV);
  END();

  if (CpuFeatures::IsSupported(JSCVT)) {
    RUN();

    CHECK_EQUAL_64(expected, x0);
    CHECK_EQUAL_32(expected_z, w1);
  }
}

TEST(fjcvtzs) {
  // Simple values.
  FjcvtzsHelper(0x0000000000000000, 0, ZFlag);   // 0.0
  FjcvtzsHelper(0x0010000000000000, 0, NoFlag);  // The smallest normal value.
  FjcvtzsHelper(0x3fdfffffffffffff, 0, NoFlag);  // The value just below 0.5.
  FjcvtzsHelper(0x3fe0000000000000, 0, NoFlag);  // 0.5
  FjcvtzsHelper(0x3fe0000000000001, 0, NoFlag);  // The value just above 0.5.
  FjcvtzsHelper(0x3fefffffffffffff, 0, NoFlag);  // The value just below 1.0.
  FjcvtzsHelper(0x3ff0000000000000, 1, ZFlag);   // 1.0
  FjcvtzsHelper(0x3ff0000000000001, 1, NoFlag);  // The value just above 1.0.
  FjcvtzsHelper(0x3ff8000000000000, 1, NoFlag);  // 1.5
  FjcvtzsHelper(0x4024000000000000, 10, ZFlag);  // 10
  FjcvtzsHelper(0x7fefffffffffffff, 0, NoFlag);  // The largest finite value.

  // Infinity.
  FjcvtzsHelper(0x7ff0000000000000, 0, NoFlag);

  // NaNs.
  //  - Quiet NaNs
  FjcvtzsHelper(0x7ff923456789abcd, 0, NoFlag);
  FjcvtzsHelper(0x7ff8000000000000, 0, NoFlag);
  //  - Signalling NaNs
  FjcvtzsHelper(0x7ff123456789abcd, 0, NoFlag);
  FjcvtzsHelper(0x7ff0000000000001, 0, NoFlag);

  // Subnormals.
  //  - A recognisable bit pattern.
  FjcvtzsHelper(0x000123456789abcd, 0, NoFlag);
  //  - The largest subnormal value.
  FjcvtzsHelper(0x000fffffffffffff, 0, NoFlag);
  //  - The smallest subnormal value.
  FjcvtzsHelper(0x0000000000000001, 0, NoFlag);

  // The same values again, but negated.
  FjcvtzsHelper(0x8000000000000000, 0, NoFlag);
  FjcvtzsHelper(0x8010000000000000, 0, NoFlag);
  FjcvtzsHelper(0xbfdfffffffffffff, 0, NoFlag);
  FjcvtzsHelper(0xbfe0000000000000, 0, NoFlag);
  FjcvtzsHelper(0xbfe0000000000001, 0, NoFlag);
  FjcvtzsHelper(0xbfefffffffffffff, 0, NoFlag);
  FjcvtzsHelper(0xbff0000000000000, 0xffffffff, ZFlag);
  FjcvtzsHelper(0xbff0000000000001, 0xffffffff, NoFlag);
  FjcvtzsHelper(0xbff8000000000000, 0xffffffff, NoFlag);
  FjcvtzsHelper(0xc024000000000000, 0xfffffff6, ZFlag);
  FjcvtzsHelper(0xffefffffffffffff, 0, NoFlag);
  FjcvtzsHelper(0xfff0000000000000, 0, NoFlag);
  FjcvtzsHelper(0xfff923456789abcd, 0, NoFlag);
  FjcvtzsHelper(0xfff8000000000000, 0, NoFlag);
  FjcvtzsHelper(0xfff123456789abcd, 0, NoFlag);
  FjcvtzsHelper(0xfff0000000000001, 0, NoFlag);
  FjcvtzsHelper(0x800123456789abcd, 0, NoFlag);
  FjcvtzsHelper(0x800fffffffffffff, 0, NoFlag);
  FjcvtzsHelper(0x8000000000000001, 0, NoFlag);
  // Test floating-point numbers of every possible exponent, most of the
  // expected values are zero but there is a range of exponents where the
  // results are shifted parts of this mantissa.
  uint64_t mantissa = 0x0001234567890abc;

  // Between an exponent of 0 and 52, only some of the top bits of the
  // mantissa are above the decimal position of doubles so the mantissa is
  // shifted to the right down to just those top bits. Above 52, all bits
  // of the mantissa are shifted left above the decimal position until it
  // reaches 52 + 64 where all the bits are shifted out of the range of 64-bit
  // integers.
  int first_exp_boundary = 52;
  int second_exp_boundary = first_exp_boundary + 64;
  for (int exponent = 0; exponent < 2048; exponent++) {
    int e = exponent - 1023;

    uint64_t expected = 0;
    if (e < 0) {
      expected = 0;
    } else if (e <= first_exp_boundary) {
      expected = (UINT64_C(1) << e) | (mantissa >> (52 - e));
      expected &= 0xffffffff;
    } else if (e < second_exp_boundary) {
      expected = (mantissa << (e - 52)) & 0xffffffff;
    } else {
      expected = 0;
    }

    uint64_t value = (static_cast<uint64_t>(exponent) << 52) | mantissa;
    FjcvtzsHelper(value, expected, NoFlag);
    FjcvtzsHelper(value | kDSignMask, (-expected) & 0xffffffff, NoFlag);
  }
}

TEST(fcvtzu) {
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

  __ Fcvtzu(w0, s0);
  __ Fcvtzu(w1, s1);
  __ Fcvtzu(w2, s2);
  __ Fcvtzu(w3, s3);
  __ Fcvtzu(w4, s4);
  __ Fcvtzu(w5, s5);
  __ Fcvtzu(w6, s6);
  __ Fcvtzu(w7, s7);
  __ Fcvtzu(w8, d8);
  __ Fcvtzu(w9, d9);
  __ Fcvtzu(w10, d10);
  __ Fcvtzu(w11, d11);
  __ Fcvtzu(w12, d12);
  __ Fcvtzu(w13, d13);
  __ Fcvtzu(w14, d14);
  __ Fcvtzu(w15, d15);
  __ Fcvtzu(x17, s17);
  __ Fcvtzu(x19, s19);
  __ Fcvtzu(x20, s20);
  __ Fcvtzu(x21, s21);
  __ Fcvtzu(x22, s22);
  __ Fcvtzu(x23, s23);
  __ Fcvtzu(x24, d24);
  __ Fcvtzu(x25, d25);
  __ Fcvtzu(x26, d26);
  __ Fcvtzu(x27, d27);
  __ Fcvtzu(x28, d28);

  // Save results to the scratch memory, for those that don't fit in registers.
  __ Mov(x30, scratch_base);
  __ Fcvtzu(x29, s16);
  __ Str(x29, MemOperand(x30));

  __ Fcvtzu(x29, d29);
  __ Fcvtzu(x30, d30);
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


// Test that scvtf and ucvtf can convert the 64-bit input into the expected
// value. All possible values of 'fbits' are tested. The expected value is
// modified accordingly in each case.
//
// The expected value is specified as the bit encoding of the expected double
// produced by scvtf (expected_scvtf_bits) as well as ucvtf
// (expected_ucvtf_bits).
//
// Where the input value is representable by int32_t or uint32_t, conversions
// from W registers will also be tested.
static void TestUScvtfHelper(uint64_t in,
                             uint64_t expected_scvtf_bits,
                             uint64_t expected_ucvtf_bits) {
  uint64_t u64 = in;
  uint32_t u32 = u64 & 0xFFFFFFFF;
  int64_t s64 = static_cast<int64_t>(in);
  int32_t s32 = s64 & 0x7FFFFFFF;

  bool cvtf_s32 = (s64 == s32);
  bool cvtf_u32 = (u64 == u32);

  double results_scvtf_x[65];
  double results_ucvtf_x[65];
  double results_scvtf_w[33];
  double results_ucvtf_w[33];

  SETUP();
  START();

  __ Mov(x0, reinterpret_cast<int64_t>(results_scvtf_x));
  __ Mov(x1, reinterpret_cast<int64_t>(results_ucvtf_x));
  __ Mov(x2, reinterpret_cast<int64_t>(results_scvtf_w));
  __ Mov(x3, reinterpret_cast<int64_t>(results_ucvtf_w));

  __ Mov(x10, s64);

  // Corrupt the top word, in case it is accidentally used during W-register
  // conversions.
  __ Mov(x11, 0x5555555555555555);
  __ Bfi(x11, x10, 0, kWRegSizeInBits);

  // Test integer conversions.
  __ Scvtf(d0, x10);
  __ Ucvtf(d1, x10);
  __ Scvtf(d2, w11);
  __ Ucvtf(d3, w11);
  __ Str(d0, MemOperand(x0));
  __ Str(d1, MemOperand(x1));
  __ Str(d2, MemOperand(x2));
  __ Str(d3, MemOperand(x3));

  // Test all possible values of fbits.
  for (int fbits = 1; fbits <= 32; fbits++) {
    __ Scvtf(d0, x10, fbits);
    __ Ucvtf(d1, x10, fbits);
    __ Scvtf(d2, w11, fbits);
    __ Ucvtf(d3, w11, fbits);
    __ Str(d0, MemOperand(x0, fbits * kDRegSize));
    __ Str(d1, MemOperand(x1, fbits * kDRegSize));
    __ Str(d2, MemOperand(x2, fbits * kDRegSize));
    __ Str(d3, MemOperand(x3, fbits * kDRegSize));
  }

  // Conversions from W registers can only handle fbits values <= 32, so just
  // test conversions from X registers for 32 < fbits <= 64.
  for (int fbits = 33; fbits <= 64; fbits++) {
    __ Scvtf(d0, x10, fbits);
    __ Ucvtf(d1, x10, fbits);
    __ Str(d0, MemOperand(x0, fbits * kDRegSize));
    __ Str(d1, MemOperand(x1, fbits * kDRegSize));
  }

  END();
  RUN();

  // Check the results.
  double expected_scvtf_base = base::bit_cast<double>(expected_scvtf_bits);
  double expected_ucvtf_base = base::bit_cast<double>(expected_ucvtf_bits);

  for (int fbits = 0; fbits <= 32; fbits++) {
    double expected_scvtf = expected_scvtf_base / pow(2.0, fbits);
    double expected_ucvtf = expected_ucvtf_base / pow(2.0, fbits);
    CHECK_EQUAL_FP64(expected_scvtf, results_scvtf_x[fbits]);
    CHECK_EQUAL_FP64(expected_ucvtf, results_ucvtf_x[fbits]);
    if (cvtf_s32) CHECK_EQUAL_FP64(expected_scvtf, results_scvtf_w[fbits]);
    if (cvtf_u32) CHECK_EQUAL_FP64(expected_ucvtf, results_ucvtf_w[fbits]);
  }
  for (int fbits = 33; fbits <= 64; fbits++) {
    double expected_scvtf = expected_scvtf_base / pow(2.0, fbits);
    double expected_ucvtf = expected_ucvtf_base / pow(2.0, fbits);
    CHECK_EQUAL_FP64(expected_scvtf, results_scvtf_x[fbits]);
    CHECK_EQUAL_FP64(expected_ucvtf, results_ucvtf_x[fbits]);
  }
}

TEST(scvtf_ucvtf_double) {
  INIT_V8();
  // Simple conversions of positive numbers which require no rounding; the
  // results should not depened on the rounding mode, and ucvtf and scvtf should
  // produce the same result.
  TestUScvtfHelper(0x0000000000000000, 0x0000000000000000, 0x0000000000000000);
  TestUScvtfHelper(0x0000000000000001, 0x3FF0000000000000, 0x3FF0000000000000);
  TestUScvtfHelper(0x0000000040000000, 0x41D0000000000000, 0x41D0000000000000);
  TestUScvtfHelper(0x0000000100000000, 0x41F0000000000000, 0x41F0000000000000);
  TestUScvtfHelper(0x4000000000000000, 0x43D0000000000000, 0x43D0000000000000);
  // Test mantissa extremities.
  TestUScvtfHelper(0x4000000000000400, 0x43D0000000000001, 0x43D0000000000001);
  // The largest int32_t that fits in a double.
  TestUScvtfHelper(0x000000007FFFFFFF, 0x41DFFFFFFFC00000, 0x41DFFFFFFFC00000);
  // Values that would be negative if treated as an int32_t.
  TestUScvtfHelper(0x00000000FFFFFFFF, 0x41EFFFFFFFE00000, 0x41EFFFFFFFE00000);
  TestUScvtfHelper(0x0000000080000000, 0x41E0000000000000, 0x41E0000000000000);
  TestUScvtfHelper(0x0000000080000001, 0x41E0000000200000, 0x41E0000000200000);
  // The largest int64_t that fits in a double.
  TestUScvtfHelper(0x7FFFFFFFFFFFFC00, 0x43DFFFFFFFFFFFFF, 0x43DFFFFFFFFFFFFF);
  // Check for bit pattern reproduction.
  TestUScvtfHelper(0x0123456789ABCDE0, 0x43723456789ABCDE, 0x43723456789ABCDE);
  TestUScvtfHelper(0x0000000012345678, 0x41B2345678000000, 0x41B2345678000000);

  // Simple conversions of negative int64_t values. These require no rounding,
  // and the results should not depend on the rounding mode.
  TestUScvtfHelper(0xFFFFFFFFC0000000, 0xC1D0000000000000, 0x43EFFFFFFFF80000);
  TestUScvtfHelper(0xFFFFFFFF00000000, 0xC1F0000000000000, 0x43EFFFFFFFE00000);
  TestUScvtfHelper(0xC000000000000000, 0xC3D0000000000000, 0x43E8000000000000);

  // Conversions which require rounding.
  TestUScvtfHelper(0x1000000000000000, 0x43B0000000000000, 0x43B0000000000000);
  TestUScvtfHelper(0x1000000000000001, 0x43B0000000000000, 0x43B0000000000000);
  TestUScvtfHelper(0x1000000000000080, 0x43B0000000000000, 0x43B0000000000000);
  TestUScvtfHelper(0x1000000000000081, 0x43B0000000000001, 0x43B0000000000001);
  TestUScvtfHelper(0x1000000000000100, 0x43B0000000000001, 0x43B0000000000001);
  TestUScvtfHelper(0x1000000000000101, 0x43B0000000000001, 0x43B0000000000001);
  TestUScvtfHelper(0x1000000000000180, 0x43B0000000000002, 0x43B0000000000002);
  TestUScvtfHelper(0x1000000000000181, 0x43B0000000000002, 0x43B0000000000002);
  TestUScvtfHelper(0x1000000000000200, 0x43B0000000000002, 0x43B0000000000002);
  TestUScvtfHelper(0x1000000000000201, 0x43B0000000000002, 0x43B0000000000002);
  TestUScvtfHelper(0x1000000000000280, 0x43B0000000000002, 0x43B0000000000002);
  TestUScvtfHelper(0x1000000000000281, 0x43B0000000000003, 0x43B0000000000003);
  TestUScvtfHelper(0x1000000000000300, 0x43B0000000000003, 0x43B0000000000003);
  // Check rounding of negative int64_t values (and large uint64_t values).
  TestUScvtfHelper(0x8000000000000000, 0xC3E0000000000000, 0x43E0000000000000);
  TestUScvtfHelper(0x8000000000000001, 0xC3E0000000000000, 0x43E0000000000000);
  TestUScvtfHelper(0x8000000000000200, 0xC3E0000000000000, 0x43E0000000000000);
  TestUScvtfHelper(0x8000000000000201, 0xC3DFFFFFFFFFFFFF, 0x43E0000000000000);
  TestUScvtfHelper(0x8000000000000400, 0xC3DFFFFFFFFFFFFF, 0x43E0000000000000);
  TestUScvtfHelper(0x8000000000000401, 0xC3DFFFFFFFFFFFFF, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000600, 0xC3DFFFFFFFFFFFFE, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000601, 0xC3DFFFFFFFFFFFFE, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000800, 0xC3DFFFFFFFFFFFFE, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000801, 0xC3DFFFFFFFFFFFFE, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000A00, 0xC3DFFFFFFFFFFFFE, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000A01, 0xC3DFFFFFFFFFFFFD, 0x43E0000000000001);
  TestUScvtfHelper(0x8000000000000C00, 0xC3DFFFFFFFFFFFFD, 0x43E0000000000002);
  // Round up to produce a result that's too big for the input to represent.
  TestUScvtfHelper(0x7FFFFFFFFFFFFE00, 0x43E0000000000000, 0x43E0000000000000);
  TestUScvtfHelper(0x7FFFFFFFFFFFFFFF, 0x43E0000000000000, 0x43E0000000000000);
  TestUScvtfHelper(0xFFFFFFFFFFFFFC00, 0xC090000000000000, 0x43F0000000000000);
  TestUScvtfHelper(0xFFFFFFFFFFFFFFFF, 0xBFF0000000000000, 0x43F0000000000000);
}

// The same as TestUScvtfHelper, but convert to floats.
static void TestUScvtf32Helper(uint64_t in,
                               uint32_t expected_scvtf_bits,
                               uint32_t expected_ucvtf_bits) {
  uint64_t u64 = in;
  uint32_t u32 = u64 & 0xFFFFFFFF;
  int64_t s64 = static_cast<int64_t>(in);
  int32_t s32 = s64 & 0x7FFFFFFF;

  bool cvtf_s32 = (s64 == s32);
  bool cvtf_u32 = (u64 == u32);

  float results_scvtf_x[65];
  float results_ucvtf_x[65];
  float results_scvtf_w[33];
  float results_ucvtf_w[33];

  SETUP();
  START();

  __ Mov(x0, reinterpret_cast<int64_t>(results_scvtf_x));
  __ Mov(x1, reinterpret_cast<int64_t>(results_ucvtf_x));
  __ Mov(x2, reinterpret_cast<int64_t>(results_scvtf_w));
  __ Mov(x3, reinterpret_cast<int64_t>(results_ucvtf_w));

  __ Mov(x10, s64);

  // Corrupt the top word, in case it is accidentally used during W-register
  // conversions.
  __ Mov(x11, 0x5555555555555555);
  __ Bfi(x11, x10, 0, kWRegSizeInBits);

  // Test integer conversions.
  __ Scvtf(s0, x10);
  __ Ucvtf(s1, x10);
  __ Scvtf(s2, w11);
  __ Ucvtf(s3, w11);
  __ Str(s0, MemOperand(x0));
  __ Str(s1, MemOperand(x1));
  __ Str(s2, MemOperand(x2));
  __ Str(s3, MemOperand(x3));

  // Test all possible values of fbits.
  for (int fbits = 1; fbits <= 32; fbits++) {
    __ Scvtf(s0, x10, fbits);
    __ Ucvtf(s1, x10, fbits);
    __ Scvtf(s2, w11, fbits);
    __ Ucvtf(s3, w11, fbits);
    __ Str(s0, MemOperand(x0, fbits * kSRegSize));
    __ Str(s1, MemOperand(x1, fbits * kSRegSize));
    __ Str(s2, MemOperand(x2, fbits * kSRegSize));
    __ Str(s3, MemOperand(x3, fbits * kSRegSize));
  }

  // Conversions from W registers can only handle fbits values <= 32, so just
  // test conversions from X registers for 32 < fbits <= 64.
  for (int fbits = 33; fbits <= 64; fbits++) {
    __ Scvtf(s0, x10, fbits);
    __ Ucvtf(s1, x10, fbits);
    __ Str(s0, MemOperand(x0, fbits * kSRegSize));
    __ Str(s1, MemOperand(x1, fbits * kSRegSize));
  }

  END();
  RUN();

  // Check the results.
  float expected_scvtf_base = base::bit_cast<float>(expected_scvtf_bits);
  float expected_ucvtf_base = base::bit_cast<float>(expected_ucvtf_bits);

  for (int fbits = 0; fbits <= 32; fbits++) {
    float expected_scvtf = expected_scvtf_base / powf(2, fbits);
    float expected_ucvtf = expected_ucvtf_base / powf(2, fbits);
    CHECK_EQUAL_FP32(expected_scvtf, results_scvtf_x[fbits]);
    CHECK_EQUAL_FP32(expected_ucvtf, results_ucvtf_x[fbits]);
    if (cvtf_s32) CHECK_EQUAL_FP32(expected_scvtf, results_scvtf_w[fbits]);
    if (cvtf_u32) CHECK_EQUAL_FP32(expected_ucvtf, results_ucvtf_w[fbits]);
  }
  for (int fbits = 33; fbits <= 64; fbits++) {
    float expected_scvtf = expected_scvtf_base / powf(2, fbits);
    float expected_ucvtf = expected_ucvtf_base / powf(2, fbits);
    CHECK_EQUAL_FP32(expected_scvtf, results_scvtf_x[fbits]);
    CHECK_EQUAL_FP32(expected_ucvtf, results_ucvtf_x[fbits]);
  }
}

TEST(scvtf_ucvtf_float) {
  INIT_V8();
  // Simple conversions of positive numbers which require no rounding; the
  // results should not depened on the rounding mode, and ucvtf and scvtf should
  // produce the same result.
  TestUScvtf32Helper(0x0000000000000000, 0x00000000, 0x00000000);
  TestUScvtf32Helper(0x0000000000000001, 0x3F800000, 0x3F800000);
  TestUScvtf32Helper(0x0000000040000000, 0x4E800000, 0x4E800000);
  TestUScvtf32Helper(0x0000000100000000, 0x4F800000, 0x4F800000);
  TestUScvtf32Helper(0x4000000000000000, 0x5E800000, 0x5E800000);
  // Test mantissa extremities.
  TestUScvtf32Helper(0x0000000000800001, 0x4B000001, 0x4B000001);
  TestUScvtf32Helper(0x4000008000000000, 0x5E800001, 0x5E800001);
  // The largest int32_t that fits in a float.
  TestUScvtf32Helper(0x000000007FFFFF80, 0x4EFFFFFF, 0x4EFFFFFF);
  // Values that would be negative if treated as an int32_t.
  TestUScvtf32Helper(0x00000000FFFFFF00, 0x4F7FFFFF, 0x4F7FFFFF);
  TestUScvtf32Helper(0x0000000080000000, 0x4F000000, 0x4F000000);
  TestUScvtf32Helper(0x0000000080000100, 0x4F000001, 0x4F000001);
  // The largest int64_t that fits in a float.
  TestUScvtf32Helper(0x7FFFFF8000000000, 0x5EFFFFFF, 0x5EFFFFFF);
  // Check for bit pattern reproduction.
  TestUScvtf32Helper(0x0000000000876543, 0x4B076543, 0x4B076543);

  // Simple conversions of negative int64_t values. These require no rounding,
  // and the results should not depend on the rounding mode.
  TestUScvtf32Helper(0xFFFFFC0000000000, 0xD4800000, 0x5F7FFFFC);
  TestUScvtf32Helper(0xC000000000000000, 0xDE800000, 0x5F400000);

  // Conversions which require rounding.
  TestUScvtf32Helper(0x0000800000000000, 0x57000000, 0x57000000);
  TestUScvtf32Helper(0x0000800000000001, 0x57000000, 0x57000000);
  TestUScvtf32Helper(0x0000800000800000, 0x57000000, 0x57000000);
  TestUScvtf32Helper(0x0000800000800001, 0x57000001, 0x57000001);
  TestUScvtf32Helper(0x0000800001000000, 0x57000001, 0x57000001);
  TestUScvtf32Helper(0x0000800001000001, 0x57000001, 0x57000001);
  TestUScvtf32Helper(0x0000800001800000, 0x57000002, 0x57000002);
  TestUScvtf32Helper(0x0000800001800001, 0x57000002, 0x57000002);
  TestUScvtf32Helper(0x0000800002000000, 0x57000002, 0x57000002);
  TestUScvtf32Helper(0x0000800002000001, 0x57000002, 0x57000002);
  TestUScvtf32Helper(0x0000800002800000, 0x57000002, 0x57000002);
  TestUScvtf32Helper(0x0000800002800001, 0x57000003, 0x57000003);
  TestUScvtf32Helper(0x0000800003000000, 0x57000003, 0x57000003);
  // Check rounding of negative int64_t values (and large uint64_t values).
  TestUScvtf32Helper(0x8000000000000000, 0xDF000000, 0x5F000000);
  TestUScvtf32Helper(0x8000000000000001, 0xDF000000, 0x5F000000);
  TestUScvtf32Helper(0x8000004000000000, 0xDF000000, 0x5F000000);
  TestUScvtf32Helper(0x8000004000000001, 0xDEFFFFFF, 0x5F000000);
  TestUScvtf32Helper(0x8000008000000000, 0xDEFFFFFF, 0x5F000000);
  TestUScvtf32Helper(0x8000008000000001, 0xDEFFFFFF, 0x5F000001);
  TestUScvtf32Helper(0x800000C000000000, 0xDEFFFFFE, 0x5F000001);
  TestUScvtf32Helper(0x800000C000000001, 0xDEFFFFFE, 0x5F000001);
  TestUScvtf32Helper(0x8000010000000000, 0xDEFFFFFE, 0x5F000001);
  TestUScvtf32Helper(0x8000010000000001, 0xDEFFFFFE, 0x5F000001);
  TestUScvtf32Helper(0x8000014000000000, 0xDEFFFFFE, 0x5F000001);
  TestUScvtf32Helper(0x8000014000000001, 0xDEFFFFFD, 0x5F000001);
  TestUScvtf32Helper(0x8000018000000000, 0xDEFFFFFD, 0x5F000002);
  // Round up to produce a result that's too big for the input to represent.
  TestUScvtf32Helper(0x000000007FFFFFC0, 0x4F000000, 0x4F000000);
  TestUScvtf32Helper(0x000000007FFFFFFF, 0x4F000000, 0x4F000000);
  TestUScvtf32Helper(0x00000000FFFFFF80, 0x4F800000, 0x4F800000);
  TestUScvtf32Helper(0x00000000FFFFFFFF, 0x4F800000, 0x4F800000);
  TestUScvtf32Helper(0x7FFFFFC000000000, 0x5F000000, 0x5F000000);
  TestUScvtf32Helper(0x7FFFFFFFFFFFFFFF, 0x5F000000, 0x5F000000);
  TestUScvtf32Helper(0xFFFFFF8000000000, 0xD3000000, 0x5F800000);
  TestUScvtf32Helper(0xFFFFFFFFFFFFFFFF, 0xBF800000, 0x5F800000);
}

TEST(system_mrs) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 1);
  __ Mov(w2, 0x80000000);

  // Set the Z and C flags.
  __ Cmp(w0, w0);
  __ Mrs(x3, NZCV);

  // Set the N flag.
  __ Cmp(w0, w1);
  __ Mrs(x4, NZCV);

  // Set the Z, C and V flags.
  __ Adds(w0, w2, w2);
  __ Mrs(x5, NZCV);

  // Read the default FPCR.
  __ Mrs(x6, FPCR);
  END();

  RUN();

  // NZCV
  CHECK_EQUAL_32(ZCFlag, w3);
  CHECK_EQUAL_32(NFlag, w4);
  CHECK_EQUAL_32(ZCVFlag, w5);

  // FPCR
  // The default FPCR on Linux-based platforms is 0.
  CHECK_EQUAL_32(0, w6);
}

TEST(system_msr) {
  INIT_V8();
  // All FPCR fields that must be implemented: AHP, DN, FZ, RMode
  const uint64_t fpcr_core = 0x07C00000;

  // All FPCR fields (including fields which may be read-as-zero):
  //  Stride, FZ16, Len
  //  IDE, IXE, UFE, OFE, DZE, IOE
  const uint64_t fpcr_all = fpcr_core | 0x003F9F07;

  SETUP();

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 0x7FFFFFFF);

  __ Mov(x7, 0);

  __ Mov(x10, NVFlag);
  __ Cmp(w0, w0);     // Set Z and C.
  __ Msr(NZCV, x10);  // Set N and V.
  // The Msr should have overwritten every flag set by the Cmp.
  __ Cinc(x7, x7, mi);  // N
  __ Cinc(x7, x7, ne);  // !Z
  __ Cinc(x7, x7, lo);  // !C
  __ Cinc(x7, x7, vs);  // V

  __ Mov(x10, ZCFlag);
  __ Cmn(w1, w1);     // Set N and V.
  __ Msr(NZCV, x10);  // Set Z and C.
  // The Msr should have overwritten every flag set by the Cmn.
  __ Cinc(x7, x7, pl);  // !N
  __ Cinc(x7, x7, eq);  // Z
  __ Cinc(x7, x7, hs);  // C
  __ Cinc(x7, x7, vc);  // !V

  // All core FPCR fields must be writable.
  __ Mov(x8, fpcr_core);
  __ Msr(FPCR, x8);
  __ Mrs(x8, FPCR);

  // All FPCR fields, including optional ones. This part of the test doesn't
  // achieve much other than ensuring that supported fields can be cleared by
  // the next test.
  __ Mov(x9, fpcr_all);
  __ Msr(FPCR, x9);
  __ Mrs(x9, FPCR);
  __ And(x9, x9, fpcr_core);

  // The undefined bits must ignore writes.
  // It's conceivable that a future version of the architecture could use these
  // fields (making this test fail), but in the meantime this is a useful test
  // for the simulator.
  __ Mov(x10, ~fpcr_all);
  __ Msr(FPCR, x10);
  __ Mrs(x10, FPCR);

  END();

  RUN();

  // We should have incremented x7 (from 0) exactly 8 times.
  CHECK_EQUAL_64(8, x7);

  CHECK_EQUAL_64(fpcr_core, x8);
  CHECK_EQUAL_64(fpcr_core, x9);
  CHECK_EQUAL_64(0, x10);
}

TEST(system_pauth_b) {
  i::v8_flags.sim_abort_on_bad_auth = false;
  SETUP();
  START();

  // Exclude x16 and x17 from the scratch register list so we can use
  // Pac/Autib1716 safely.
  UseScratchRegisterScope temps(&masm);
  temps.Exclude(x16, x17);
  temps.Include(x10, x11);

  // Backup stack pointer.
  __ Mov(x20, sp);

  // Modifiers
  __ Mov(x16, 0x477d469dec0b8768);
  __ Mov(sp, 0x477d469dec0b8760);

  // Generate PACs using the 3 system instructions.
  __ Mov(x17, 0x0000000012345678);
  __ Pacib1716();
  __ Mov(x0, x17);

  __ Mov(lr, 0x0000000012345678);
  __ Pacibsp();
  __ Mov(x2, lr);

  // Authenticate the pointers above.
  __ Mov(x17, x0);
  __ Autib1716();
  __ Mov(x3, x17);

  __ Mov(lr, x2);
  __ Autibsp();
  __ Mov(x5, lr);

  // Attempt to authenticate incorrect pointers.
  __ Mov(x17, x2);
  __ Autib1716();
  __ Mov(x6, x17);

  __ Mov(lr, x0);
  __ Autibsp();
  __ Mov(x8, lr);

  // Restore stack pointer.
  __ Mov(sp, x20);

  // Mask out just the PAC code bits.
  __ And(x0, x0, 0x007f000000000000);
  __ And(x2, x2, 0x007f000000000000);

  END();

// TODO(all): test on real hardware when available
#ifdef USE_SIMULATOR
  RUN();

  // Check PAC codes have been generated and aren't equal.
  // NOTE: with a different ComputePAC implementation, there may be a collision.
  CHECK_NE(0, core.xreg(2));
  CHECK_NOT_ZERO_AND_NOT_EQUAL_64(x0, x2);

  // Pointers correctly authenticated.
  CHECK_EQUAL_64(0x0000000012345678, x3);
  CHECK_EQUAL_64(0x0000000012345678, x5);

  // Pointers corrupted after failing to authenticate.
  CHECK_EQUAL_64(0x0040000012345678, x6);
  CHECK_EQUAL_64(0x0040000012345678, x8);

#endif  // USE_SIMULATOR
}

TEST(system) {
  INIT_V8();
  SETUP();
  RegisterDump before;

  START();
  before.Dump(&masm);
  __ Nop();
  __ Csdb();
  END();

  RUN();

  CHECK_EQUAL_REGISTERS(before);
  CHECK_EQUAL_NZCV(before.flags_nzcv());
}

TEST(zero_dest) {
  INIT_V8();
  SETUP();
  RegisterDump before;

  START();
  // Preserve the system stack pointer, in case we clobber it.
  __ Mov(x30, sp);
  // Initialize the other registers used in this test.
  uint64_t literal_base = 0x0100001000100101UL;
  __ Mov(x0, 0);
  __ Mov(x1, literal_base);
  for (int i = 2; i < x30.code(); i++) {
    // Skip x18, the platform register.
    if (i == 18) continue;
    __ Add(Register::XRegFromCode(i), Register::XRegFromCode(i-1), x1);
  }
  before.Dump(&masm);

  // All of these instructions should be NOPs in these forms, but have
  // alternate forms which can write into the stack pointer.
  __ add(xzr, x0, x1);
  __ add(xzr, x1, xzr);
  __ add(xzr, xzr, x1);

  __ and_(xzr, x0, x2);
  __ and_(xzr, x2, xzr);
  __ and_(xzr, xzr, x2);

  __ bic(xzr, x0, x3);
  __ bic(xzr, x3, xzr);
  __ bic(xzr, xzr, x3);

  __ eon(xzr, x0, x4);
  __ eon(xzr, x4, xzr);
  __ eon(xzr, xzr, x4);

  __ eor(xzr, x0, x5);
  __ eor(xzr, x5, xzr);
  __ eor(xzr, xzr, x5);

  __ orr(xzr, x0, x6);
  __ orr(xzr, x6, xzr);
  __ orr(xzr, xzr, x6);

  __ sub(xzr, x0, x7);
  __ sub(xzr, x7, xzr);
  __ sub(xzr, xzr, x7);

  // Swap the saved system stack pointer with the real one. If sp was written
  // during the test, it will show up in x30. This is done because the test
  // framework assumes that sp will be valid at the end of the test.
  __ Mov(x29, x30);
  __ Mov(x30, sp);
  __ Mov(sp, x29);
  // We used x29 as a scratch register, so reset it to make sure it doesn't
  // trigger a test failure.
  __ Add(x29, x28, x1);
  END();

  RUN();

  CHECK_EQUAL_REGISTERS(before);
  CHECK_EQUAL_NZCV(before.flags_nzcv());
}

TEST(zero_dest_setflags) {
  INIT_V8();
  SETUP();
  RegisterDump before;

  START();
  // Preserve the system stack pointer, in case we clobber it.
  __ Mov(x30, sp);
  // Initialize the other registers used in this test.
  uint64_t literal_base = 0x0100001000100101UL;
  __ Mov(x0, 0);
  __ Mov(x1, literal_base);
  for (int i = 2; i < 30; i++) {
    // Skip x18, the platform register.
    if (i == 18) continue;
    __ Add(Register::XRegFromCode(i), Register::XRegFromCode(i-1), x1);
  }
  before.Dump(&masm);

  // All of these instructions should only write to th
```