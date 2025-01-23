Response: The user wants to understand the functionality of a C++ source code file related to ARM64 assembly testing within the V8 JavaScript engine.

The request asks for:
1. A summary of the file's functionality.
2. Explanation of its relation to JavaScript.
3. A JavaScript example illustrating the connection (if any).
4. Confirmation that this is part 6 of an 8-part series.

Based on the code snippet, this file seems to contain a series of unit tests for the ARM64 assembler within V8. The tests cover various ARM64 instructions, specifically focusing on floating-point conversions (like `fcvtnu`, `fcvtzs`, `fcvtzu`, `scvtf`, `ucvtf`), system instructions (`mrs`, `msr`, `pauth`), and stack manipulation instructions (`push`, `pop`, `copy_slots`).

The connection to JavaScript lies in the fact that V8 is the JavaScript engine used in Chrome and Node.js. This assembler is used by the V8 compiler (TurboFan) to generate native machine code from JavaScript. The tests ensure that the assembler correctly implements the ARM64 instruction set, which is crucial for the performance and correctness of JavaScript execution on ARM64 architectures.

Let's break down the specific tests and then formulate the JavaScript example.

- **Floating-point conversions (`fcvtnu`, `fcvtzs`, `fcvtzu`, `fjcvtzs`):** These tests verify the instructions that convert floating-point numbers to integers (unsigned and signed, with different rounding modes).
- **`scvtf`, `ucvtf`:** These test the conversion of integer values (signed and unsigned) to floating-point numbers.
- **System instructions (`mrs`, `msr`):** These tests verify reading from and writing to system registers, such as the flags register (NZCV) and the floating-point control register (FPCR).
- **Pointer Authentication (`pauth_b`):** This test checks the functionality of ARM's Pointer Authentication mechanism for branch addresses.
- **Stack manipulation (`push`, `pop`, `copy_slots`, `copy_double_words`):** These tests cover instructions for managing the stack, including pushing and popping registers, and copying data within the stack.
- **Register tests (`register_bit`, `vreg`):** These are more about the internal representation and manipulation of registers within the assembler.
- **`peek_poke`:** These tests simulate reading from and writing to memory locations using register values as addresses.
- **Zero destination register tests (`zero_dest`, `zero_dest_setflags`):** These ensure that operations with the zero register as a destination behave as expected (typically as no-ops for data writes, but potentially affecting flags).

A JavaScript example demonstrating the impact of these instructions might involve operations that inherently rely on floating-point conversions or benefit from optimized native code generation.

For example, consider a JavaScript function that performs a floating-point calculation and then converts the result to an integer. The V8 engine, when optimizing this function, might use instructions like `fcvtzs` or `fcvtnu` under the hood.
这个C++源代码文件 `v8/test/cctest/test-assembler-arm64.cc` 的第6部分主要用于测试 **ARM64汇编器中浮点数和整数之间转换指令的功能**。它通过编写一系列的汇编代码片段，执行这些代码，并检查执行后的寄存器状态，以此验证汇编器生成的指令是否按照预期工作。

具体来说，这部分测试涵盖了以下指令：

* **`Fcvtnu` (浮点数转换为无符号整数，向零舍入):**  测试将浮点寄存器中的值转换为无符号整数并存储到通用寄存器中。
* **`Fcvtzs` (浮点数转换为有符号整数，向零舍入):** 测试将浮点寄存器中的值转换为有符号整数并存储到通用寄存器中。
* **`Fjcvtzs` (JavaScript 浮点数转换为有符号整数，向零舍入):**  这个测试特别针对 V8 引擎，验证了针对 JavaScript 浮点数到有符号整数转换的优化指令。它会检查转换结果以及是否正确设置了零标志位。
* **`Fcvtzu` (浮点数转换为无符号整数，向零舍入):** 类似于 `Fcvtnu`，测试浮点数到无符号整数的转换。
* **`Scvtf` (有符号整数转换为浮点数):** 测试将有符号整数转换为浮点数。
* **`Ucvtf` (无符号整数转换为浮点数):** 测试将无符号整数转换为浮点数。

**它与 JavaScript 的功能有直接关系。**  JavaScript 是一种动态类型的语言，其数字类型在内部通常以浮点数（double）表示。当 JavaScript 代码需要将浮点数转换为整数，或者将整数转换为浮点数时，V8 引擎在底层会使用这些 ARM64 汇编指令来实现高效的转换。

**JavaScript 举例说明：**

假设有以下 JavaScript 代码：

```javascript
function floatToInt(floatNum) {
  return Math.trunc(floatNum); // 使用 Math.trunc 进行浮点数到整数的转换
}

function intToFloat(intNum) {
  return intNum * 1.0; // 乘以 1.0 将整数转换为浮点数
}

let floatValue = 3.14;
let intValue = 10;

let integerResult = floatToInt(floatValue);
let floatResult = intToFloat(intValue);

console.log(integerResult); // 输出 3
console.log(floatResult);   // 输出 10
```

当 V8 引擎执行 `floatToInt` 函数时，对于 `Math.trunc(floatNum)` 这样的操作，在 ARM64 架构上，V8 的编译器 (TurboFan) 很可能会生成类似 `Fcvtzs` 或 `Fcvtnu` 这样的汇编指令来完成浮点数到整数的转换 (具体使用哪个指令取决于是否需要保留符号)。

同样，当执行 `intToFloat` 函数时，对于 `intValue * 1.0` 这样的操作，V8 可能会生成 `Scvtf` 或 `Ucvtf` 这样的汇编指令来将整数转换为浮点数。

**总结一下第6部分的功能：**

这部分代码是 V8 引擎针对 ARM64 架构汇编器的单元测试，专注于验证浮点数和整数之间各种转换指令的正确性。这些测试对于确保 JavaScript 代码在 ARM64 平台上高效且准确地执行至关重要，因为 JavaScript 中频繁涉及到数字类型之间的转换。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```
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

  // All of these instructions should only write to the flags in these forms,
  // but have alternate forms which can write into the stack pointer.
  __ adds(xzr, x0, Operand(x1, UXTX));
  __ adds(xzr, x1, Operand(xzr, UXTX));
  __ adds(xzr, x1, 1234);
  __ adds(xzr, x0, x1);
  __ adds(xzr, x1, xzr);
  __ adds(xzr, xzr, x1);

  __ ands(xzr, x2, ~0xF);
  __ ands(xzr, xzr, ~0xF);
  __ ands(xzr, x0, x2);
  __ ands(xzr, x2, xzr);
  __ ands(xzr, xzr, x2);

  __ bics(xzr, x3, ~0xF);
  __ bics(xzr, xzr, ~0xF);
  __ bics(xzr, x0, x3);
  __ bics(xzr, x3, xzr);
  __ bics(xzr, xzr, x3);

  __ subs(xzr, x0, Operand(x3, UXTX));
  __ subs(xzr, x3, Operand(xzr, UXTX));
  __ subs(xzr, x3, 1234);
  __ subs(xzr, x0, x3);
  __ subs(xzr, x3, xzr);
  __ subs(xzr, xzr, x3);

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
}

TEST(register_bit) {
  // No code generation takes place in this test, so no need to setup and
  // teardown.

  // Simple tests.
  CHECK_EQ(RegList{x0}.bits(), 1ULL << 0);
  CHECK_EQ(RegList{x1}.bits(), 1ULL << 1);
  CHECK_EQ(RegList{x10}.bits(), 1ULL << 10);

  // AAPCS64 definitions.
  CHECK_EQ(RegList{fp}.bits(), 1ULL << kFramePointerRegCode);
  CHECK_EQ(RegList{lr}.bits(), 1ULL << kLinkRegCode);

  // Fixed (hardware) definitions.
  CHECK_EQ(RegList{xzr}.bits(), 1ULL << kZeroRegCode);

  // Internal ABI definitions.
  CHECK_EQ(RegList{sp}.bits(), 1ULL << kSPRegInternalCode);
  CHECK_NE(RegList{sp}.bits(), RegList{xzr}.bits());

  // RegList{xn}.bits() == RegList{wn}.bits() at all times, for the same n.
  CHECK_EQ(RegList{x0}.bits(), RegList{w0}.bits());
  CHECK_EQ(RegList{x1}.bits(), RegList{w1}.bits());
  CHECK_EQ(RegList{x10}.bits(), RegList{w10}.bits());
  CHECK_EQ(RegList{xzr}.bits(), RegList{wzr}.bits());
  CHECK_EQ(RegList{sp}.bits(), RegList{wsp}.bits());
}

TEST(peek_poke_simple) {
  INIT_V8();
  SETUP();
  START();

  static const RegList x0_to_x3 = {x0, x1, x2, x3};
  static const RegList x10_to_x13 = {x10, x11, x12, x13};

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  // Initialize the registers.
  __ Mov(x0, literal_base);
  __ Add(x1, x0, x0);
  __ Add(x2, x1, x0);
  __ Add(x3, x2, x0);

  __ Claim(4);

  // Simple exchange.
  //  After this test:
  //    x0-x3 should be unchanged.
  //    w10-w13 should contain the lower words of x0-x3.
  __ Poke(x0, 0);
  __ Poke(x1, 8);
  __ Poke(x2, 16);
  __ Poke(x3, 24);
  Clobber(&masm, x0_to_x3);
  __ Peek(x0, 0);
  __ Peek(x1, 8);
  __ Peek(x2, 16);
  __ Peek(x3, 24);

  __ Poke(w0, 0);
  __ Poke(w1, 4);
  __ Poke(w2, 8);
  __ Poke(w3, 12);
  Clobber(&masm, x10_to_x13);
  __ Peek(w10, 0);
  __ Peek(w11, 4);
  __ Peek(w12, 8);
  __ Peek(w13, 12);

  __ Drop(4);

  END();
  RUN();

  CHECK_EQUAL_64(literal_base * 1, x0);
  CHECK_EQUAL_64(literal_base * 2, x1);
  CHECK_EQUAL_64(literal_base * 3, x2);
  CHECK_EQUAL_64(literal_base * 4, x3);

  CHECK_EQUAL_64((literal_base * 1) & 0xFFFFFFFF, x10);
  CHECK_EQUAL_64((literal_base * 2) & 0xFFFFFFFF, x11);
  CHECK_EQUAL_64((literal_base * 3) & 0xFFFFFFFF, x12);
  CHECK_EQUAL_64((literal_base * 4) & 0xFFFFFFFF, x13);
}

TEST(peek_poke_unaligned) {
  INIT_V8();
  SETUP();
  START();

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  // Initialize the registers.
  __ Mov(x0, literal_base);
  __ Add(x1, x0, x0);
  __ Add(x2, x1, x0);
  __ Add(x3, x2, x0);
  __ Add(x4, x3, x0);
  __ Add(x5, x4, x0);
  __ Add(x6, x5, x0);

  __ Claim(4);

  // Unaligned exchanges.
  //  After this test:
  //    x0-x6 should be unchanged.
  //    w10-w12 should contain the lower words of x0-x2.
  __ Poke(x0, 1);
  Clobber(&masm, RegList{x0});
  __ Peek(x0, 1);
  __ Poke(x1, 2);
  Clobber(&masm, RegList{x1});
  __ Peek(x1, 2);
  __ Poke(x2, 3);
  Clobber(&masm, RegList{x2});
  __ Peek(x2, 3);
  __ Poke(x3, 4);
  Clobber(&masm, RegList{x3});
  __ Peek(x3, 4);
  __ Poke(x4, 5);
  Clobber(&masm, RegList{x4});
  __ Peek(x4, 5);
  __ Poke(x5, 6);
  Clobber(&masm, RegList{x5});
  __ Peek(x5, 6);
  __ Poke(x6, 7);
  Clobber(&masm, RegList{x6});
  __ Peek(x6, 7);

  __ Poke(w0, 1);
  Clobber(&masm, RegList{w10});
  __ Peek(w10, 1);
  __ Poke(w1, 2);
  Clobber(&masm, RegList{w11});
  __ Peek(w11, 2);
  __ Poke(w2, 3);
  Clobber(&masm, RegList{w12});
  __ Peek(w12, 3);

  __ Drop(4);

  END();
  RUN();

  CHECK_EQUAL_64(literal_base * 1, x0);
  CHECK_EQUAL_64(literal_base * 2, x1);
  CHECK_EQUAL_64(literal_base * 3, x2);
  CHECK_EQUAL_64(literal_base * 4, x3);
  CHECK_EQUAL_64(literal_base * 5, x4);
  CHECK_EQUAL_64(literal_base * 6, x5);
  CHECK_EQUAL_64(literal_base * 7, x6);

  CHECK_EQUAL_64((literal_base * 1) & 0xFFFFFFFF, x10);
  CHECK_EQUAL_64((literal_base * 2) & 0xFFFFFFFF, x11);
  CHECK_EQUAL_64((literal_base * 3) & 0xFFFFFFFF, x12);
}

TEST(peek_poke_endianness) {
  INIT_V8();
  SETUP();
  START();

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  // Initialize the registers.
  __ Mov(x0, literal_base);
  __ Add(x1, x0, x0);

  __ Claim(4);

  // Endianness tests.
  //  After this section:
  //    x4 should match x0[31:0]:x0[63:32]
  //    w5 should match w1[15:0]:w1[31:16]
  __ Poke(x0, 0);
  __ Poke(x0, 8);
  __ Peek(x4, 4);

  __ Poke(w1, 0);
  __ Poke(w1, 4);
  __ Peek(w5, 2);

  __ Drop(4);

  END();
  RUN();

  uint64_t x0_expected = literal_base * 1;
  uint64_t x1_expected = literal_base * 2;
  uint64_t x4_expected = (x0_expected << 32) | (x0_expected >> 32);
  uint64_t x5_expected =
      ((x1_expected << 16) & 0xFFFF0000) | ((x1_expected >> 16) & 0x0000FFFF);

  CHECK_EQUAL_64(x0_expected, x0);
  CHECK_EQUAL_64(x1_expected, x1);
  CHECK_EQUAL_64(x4_expected, x4);
  CHECK_EQUAL_64(x5_expected, x5);
}

TEST(peek_poke_mixed) {
  INIT_V8();
  SETUP();
  START();

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  // Initialize the registers.
  __ Mov(x0, literal_base);
  __ Add(x1, x0, x0);
  __ Add(x2, x1, x0);
  __ Add(x3, x2, x0);

  __ Claim(4);

  // Mix with other stack operations.
  //  After this section:
  //    x0-x3 should be unchanged.
  //    x6 should match x1[31:0]:x0[63:32]
  //    w7 should match x1[15:0]:x0[63:48]
  __ Poke(x1, 8);
  __ Poke(x0, 0);
  {
    __ Peek(x6, 4);
    __ Peek(w7, 6);
    __ Poke(xzr, 0);    // Clobber the space we're about to drop.
    __ Poke(xzr, 8);    // Clobber the space we're about to drop.
    __ Drop(2);
    __ Poke(x3, 8);
    __ Poke(x2, 0);
    __ Claim(2);
    __ Poke(x0, 0);
    __ Poke(x1, 8);
  }

  __ Pop(x0, x1, x2, x3);

  END();
  RUN();

  uint64_t x0_expected = literal_base * 1;
  uint64_t x1_expected = literal_base * 2;
  uint64_t x2_expected = literal_base * 3;
  uint64_t x3_expected = literal_base * 4;
  uint64_t x6_expected = (x1_expected << 32) | (x0_expected >> 32);
  uint64_t x7_expected =
      ((x1_expected << 16) & 0xFFFF0000) | ((x0_expected >> 48) & 0x0000FFFF);

  CHECK_EQUAL_64(x0_expected, x0);
  CHECK_EQUAL_64(x1_expected, x1);
  CHECK_EQUAL_64(x2_expected, x2);
  CHECK_EQUAL_64(x3_expected, x3);
  CHECK_EQUAL_64(x6_expected, x6);
  CHECK_EQUAL_64(x7_expected, x7);
}

// This enum is used only as an argument to the push-pop test helpers.
enum PushPopMethod {
  // Push or Pop using the Push and Pop methods, with blocks of up to four
  // registers. (Smaller blocks will be used if necessary.)
  PushPopByFour,

  // Use Push<Size>RegList and Pop<Size>RegList to transfer the registers.
  PushPopRegList
};

// The maximum number of registers that can be used by the PushPop* tests,
// where a reg_count field is provided.
static int const kPushPopMaxRegCount = -1;

// Test a simple push-pop pattern:
//  * Push <reg_count> registers with size <reg_size>.
//  * Clobber the register contents.
//  * Pop <reg_count> registers to restore the original contents.
//
// Different push and pop methods can be specified independently to test for
// proper word-endian behaviour.
static void PushPopSimpleHelper(int reg_count, int reg_size,
                                PushPopMethod push_method,
                                PushPopMethod pop_method) {
  SETUP();

  START();

  // Registers in the TmpList can be used by the macro assembler for debug code
  // (for example in 'Pop'), so we can't use them here.
  // x18 is reserved for the platform register.
  // For simplicity, exclude LR as well, as we would need to sign it when
  // pushing it. This also ensures that the list has an even number of elements,
  // which is needed for alignment.
  static RegList const allowed =
      RegList::FromBits(static_cast<uint32_t>(~masm.TmpList()->bits())) -
      RegList{x18, lr};
  if (reg_count == kPushPopMaxRegCount) {
    reg_count = CountSetBits(allowed.bits(), kNumberOfRegisters);
  }
  DCHECK_EQ(reg_count % 2, 0);
  // Work out which registers to use, based on reg_size.
  auto r = CreateRegisterArray<Register, kNumberOfRegisters>();
  auto x = CreateRegisterArray<Register, kNumberOfRegisters>();
  RegList list = PopulateRegisterArray(nullptr, x.data(), r.data(), reg_size,
                                       reg_count, allowed);

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  {
    int i;

    // Initialize the registers.
    for (i = 0; i < reg_count; i++) {
      // Always write into the X register, to ensure that the upper word is
      // properly ignored by Push when testing W registers.
      if (!x[i].IsZero()) {
        __ Mov(x[i], literal_base * i);
      }
    }

    switch (push_method) {
      case PushPopByFour:
        // Push high-numbered registers first (to the highest addresses).
        for (i = reg_count; i >= 4; i -= 4) {
          __ Push<MacroAssembler::kDontStoreLR>(r[i - 1], r[i - 2], r[i - 3],
                                                r[i - 4]);
        }
        // Finish off the leftovers.
        switch (i) {
          case 3:  __ Push(r[2], r[1], r[0]); break;
          case 2:  __ Push(r[1], r[0]);       break;
          case 1:  __ Push(r[0]);             break;
          default:
            CHECK_EQ(i, 0);
            break;
        }
        break;
      case PushPopRegList:
        __ PushSizeRegList(list, reg_size);
        break;
    }

    // Clobber all the registers, to ensure that they get repopulated by Pop.
    Clobber(&masm, list);

    switch (pop_method) {
      case PushPopByFour:
        // Pop low-numbered registers first (from the lowest addresses).
        for (i = 0; i <= (reg_count-4); i += 4) {
          __ Pop<MacroAssembler::kDontLoadLR>(r[i], r[i + 1], r[i + 2],
                                              r[i + 3]);
        }
        // Finish off the leftovers.
        switch (reg_count - i) {
          case 3:  __ Pop(r[i], r[i+1], r[i+2]); break;
          case 2:  __ Pop(r[i], r[i+1]);         break;
          case 1:  __ Pop(r[i]);                 break;
          default:
            CHECK_EQ(i, reg_count);
            break;
        }
        break;
      case PushPopRegList:
        __ PopSizeRegList(list, reg_size);
        break;
    }
  }

  END();

  RUN();

  // Check that the register contents were preserved.
  // Always use CHECK_EQUAL_64, even when testing W registers, so we can test
  // that the upper word was properly cleared by Pop.
  literal_base &= (0xFFFFFFFFFFFFFFFFUL >> (64 - reg_size));
  for (int i = 0; i < reg_count; i++) {
    if (x[i].IsZero()) {
      CHECK_EQUAL_64(0, x[i]);
    } else {
      CHECK_EQUAL_64(literal_base * i, x[i]);
    }
  }
}

TEST(push_pop_simple_32) {
  INIT_V8();

  for (int count = 0; count < kPushPopMaxRegCount; count += 4) {
    PushPopSimpleHelper(count, kWRegSizeInBits, PushPopByFour, PushPopByFour);
    PushPopSimpleHelper(count, kWRegSizeInBits, PushPopByFour, PushPopRegList);
    PushPopSimpleHelper(count, kWRegSizeInBits, PushPopRegList, PushPopByFour);
    PushPopSimpleHelper(count, kWRegSizeInBits, PushPopRegList, PushPopRegList);
  }
  // Skip testing kPushPopMaxRegCount, as we exclude the temporary registers
  // and we end up with a number of registers that is not a multiple of four and
  // is not supported for pushing.
}

TEST(push_pop_simple_64) {
  INIT_V8();
  for (int count = 0; count <= 8; count += 2) {
    PushPopSimpleHelper(count, kXRegSizeInBits, PushPopByFour, PushPopByFour);
    PushPopSimpleHelper(count, kXRegSizeInBits, PushPopByFour, PushPopRegList);
    PushPopSimpleHelper(count, kXRegSizeInBits, PushPopRegList, PushPopByFour);
    PushPopSimpleHelper(count, kXRegSizeInBits, PushPopRegList, PushPopRegList);
  }
  // Test with the maximum number of registers.
  PushPopSimpleHelper(kPushPopMaxRegCount, kXRegSizeInBits, PushPopByFour,
                      PushPopByFour);
  PushPopSimpleHelper(kPushPopMaxRegCount, kXRegSizeInBits, PushPopByFour,
                      PushPopRegList);
  PushPopSimpleHelper(kPushPopMaxRegCount, kXRegSizeInBits, PushPopRegList,
                      PushPopByFour);
  PushPopSimpleHelper(kPushPopMaxRegCount, kXRegSizeInBits, PushPopRegList,
                      PushPopRegList);
}

// The maximum number of registers that can be used by the PushPopFP* tests,
// where a reg_count field is provided.
static int const kPushPopFPMaxRegCount = -1;

// Test a simple push-pop pattern:
//  * Push <reg_count> FP registers with size <reg_size>.
//  * Clobber the register contents.
//  * Pop <reg_count> FP registers to restore the original contents.
//
// Different push and pop methods can be specified independently to test for
// proper word-endian behaviour.
static void PushPopFPSimpleHelper(int reg_count, int reg_size,
                                  PushPopMethod push_method,
                                  PushPopMethod pop_method) {
  SETUP();

  START();

  // We can use any floating-point register. None of them are reserved for
  // debug code, for example.
  static DoubleRegList const allowed = DoubleRegList::FromBits(~0);
  if (reg_count == kPushPopFPMaxRegCount) {
    reg_count = CountSetBits(allowed.bits(), kNumberOfVRegisters);
  }
  // Work out which registers to use, based on reg_size.
  auto v = CreateRegisterArray<VRegister, kNumberOfRegisters>();
  auto d = CreateRegisterArray<VRegister, kNumberOfRegisters>();
  DoubleRegList list = PopulateVRegisterArray(nullptr, d.data(), v.data(),
                                              reg_size, reg_count, allowed);

  // The literal base is chosen to have two useful properties:
  //  * When multiplied (using an integer) by small values (such as a register
  //    index), this value is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  //  * It is never a floating-point NaN, and will therefore always compare
  //    equal to itself.
  uint64_t literal_base = 0x0100001000100101UL;

  {
    int i;

    // Initialize the registers, using X registers to load the literal.
    __ Mov(x0, 0);
    __ Mov(x1, literal_base);
    for (i = 0; i < reg_count; i++) {
      // Always write into the D register, to ensure that the upper word is
      // properly ignored by Push when testing S registers.
      __ Fmov(d[i], x0);
      // Calculate the next literal.
      __ Add(x0, x0, x1);
    }

    switch (push_method) {
      case PushPopByFour:
        // Push high-numbered registers first (to the highest addresses).
        for (i = reg_count; i >= 4; i -= 4) {
          __ Push(v[i-1], v[i-2], v[i-3], v[i-4]);
        }
        // Finish off the leftovers.
        switch (i) {
          case 3:  __ Push(v[2], v[1], v[0]); break;
          case 2:  __ Push(v[1], v[0]);       break;
          case 1:  __ Push(v[0]);             break;
          default:
            CHECK_EQ(i, 0);
            break;
        }
        break;
      case PushPopRegList:
        __ PushSizeRegList(list, reg_size);
        break;
    }

    // Clobber all the registers, to ensure that they get repopulated by Pop.
    ClobberFP(&masm, list);

    switch (pop_method) {
      case PushPopByFour:
        // Pop low-numbered registers first (from the lowest addresses).
        for (i = 0; i <= (reg_count-4); i += 4) {
          __ Pop(v[i], v[i+1], v[i+2], v[i+3]);
        }
        // Finish off the leftovers.
        switch (reg_count - i) {
          case 3:  __ Pop(v[i], v[i+1], v[i+2]); break;
          case 2:  __ Pop(v[i], v[i+1]);         break;
          case 1:  __ Pop(v[i]);                 break;
          default:
            CHECK_EQ(i, reg_count);
            break;
        }
        break;
      case PushPopRegList:
        __ PopSizeRegList(list, reg_size);
        break;
    }
  }

  END();

  RUN();

  // Check that the register contents were preserved.
  // Always use CHECK_EQUAL_FP64, even when testing S registers, so we can
  // test that the upper word was properly cleared by Pop.
  literal_base &= (0xFFFFFFFFFFFFFFFFUL >> (64 - reg_size));
  for (int i = 0; i < reg_count; i++) {
    uint64_t literal = literal_base * i;
    double expected;
    memcpy(&expected, &literal, sizeof(expected));
    CHECK_EQUAL_FP64(expected, d[i]);
  }
}

TEST(push_pop_fp_simple_32) {
  INIT_V8();
  for (int count = 0; count <= 8; count += 4) {
    PushPopFPSimpleHelper(count, kSRegSizeInBits, PushPopByFour, PushPopByFour);
    PushPopFPSimpleHelper(count, kSRegSizeInBits, PushPopByFour,
                          PushPopRegList);
    PushPopFPSimpleHelper(count, kSRegSizeInBits, PushPopRegList,
                          PushPopByFour);
    PushPopFPSimpleHelper(count, kSRegSizeInBits, PushPopRegList,
                          PushPopRegList);
  }
  // Test with the maximum number of registers.
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kSRegSizeInBits, PushPopByFour,
                        PushPopByFour);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kSRegSizeInBits, PushPopByFour,
                        PushPopRegList);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kSRegSizeInBits, PushPopRegList,
                        PushPopByFour);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kSRegSizeInBits, PushPopRegList,
                        PushPopRegList);
}

TEST(push_pop_fp_simple_64) {
  INIT_V8();
  for (int count = 0; count <= 8; count += 2) {
    PushPopFPSimpleHelper(count, kDRegSizeInBits, PushPopByFour, PushPopByFour);
    PushPopFPSimpleHelper(count, kDRegSizeInBits, PushPopByFour,
                          PushPopRegList);
    PushPopFPSimpleHelper(count, kDRegSizeInBits, PushPopRegList,
                          PushPopByFour);
    PushPopFPSimpleHelper(count, kDRegSizeInBits, PushPopRegList,
                          PushPopRegList);
  }
  // Test with the maximum number of registers.
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kDRegSizeInBits, PushPopByFour,
                        PushPopByFour);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kDRegSizeInBits, PushPopByFour,
                        PushPopRegList);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kDRegSizeInBits, PushPopRegList,
                        PushPopByFour);
  PushPopFPSimpleHelper(kPushPopFPMaxRegCount, kDRegSizeInBits, PushPopRegList,
                        PushPopRegList);
}


// Push and pop data using an overlapping combination of Push/Pop and
// RegList-based methods.
static void PushPopMixedMethodsHelper(int reg_size) {
  SETUP();

  // Registers in the TmpList can be used by the macro assembler for debug code
  // (for example in 'Pop'), so we can't use them here.
  static RegList const allowed =
      RegList::FromBits(static_cast<uint32_t>(~masm.TmpList()->bits()));
  // Work out which registers to use, based on reg_size.
  auto r = CreateRegisterArray<Register, 10>();
  auto x = CreateRegisterArray<Register, 10>();
  PopulateRegisterArray(nullptr, x.data(), r.data(), reg_size, 10, allowed);

  // Calculate some handy register lists.
  RegList r0_to_r3;
  for (int i = 0; i <= 3; i++) {
    r0_to_r3.set(x[i]);
  }
  RegList r4_to_r5;
  for (int i = 4; i <= 5; i++) {
    r4_to_r5.set(x[i]);
  }
  RegList r6_to_r9;
  for (int i = 6; i <= 9; i++) {
    r6_to_r9.set(x[i]);
  }

  // The literal base is chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t literal_base = 0x0100001000100101UL;

  START();
  {
    __ Mov(x[3], literal_base * 3);
    __ Mov(x[2], literal_base * 2);
    __ Mov(x[1], literal_base * 1);
    __ Mov(x[0], literal_base * 0);

    __ PushSizeRegList(r0_to_r3, reg_size);
    __ Push(r[3], r[2]);

    Clobber(&masm, r0_to_r3);
    __ PopSizeRegList(r0_to_r3, reg_size);

    __ Push(r[2], r[1], r[3], r[0]);

    Clobber(&masm, r4_to_r5);
    __ Pop(r[4], r[5]);
    Clobber(&masm, r6_to_r9);
    __ Pop(r[6], r[7], r[8], r[9]);
  }

  END();

  RUN();

  // Always use CHECK_EQUAL_64, even when testing W registers, so we can test
  // that the upper word was properly cleared by Pop.
  literal_base &= (0xFFFFFFFFFFFFFFFFUL >> (64 - reg_size));

  CHECK_EQUAL_64(literal_base * 3, x[9]);
  CHECK_EQUAL_64(literal_base * 2, x[8]);
  CHECK_EQUAL_64(literal_base * 0, x[7]);
  CHECK_EQUAL_64(literal_base * 3, x[6]);
  CHECK_EQUAL_64(literal_base * 1, x[5]);
  CHECK_EQUAL_64(literal_base * 2, x[4]);
}

TEST(push_pop_mixed_methods_64) {
  INIT_V8();
  PushPopMixedMethodsHelper(kXRegSizeInBits);
}

TEST(push_pop) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x3, 0x3333333333333333UL);
  __ Mov(x2, 0x2222222222222222UL);
  __ Mov(x1, 0x1111111111111111UL);
  __ Mov(x0, 0x0000000000000000UL);
  __ Claim(2);
  __ PushXRegList({x0, x1, x2, x3});
  __ Push(x3, x2);
  __ PopXRegList({x0, x1, x2, x3});
  __ Push(x2, x1, x3, x0);
  __ Pop(x4, x5);
  __ Pop(x6, x7, x8, x9);

  __ Claim(2);
  __ PushWRegList({w0, w1, w2, w3});
  __ Push(w3, w1, w2, w0);
  __ PopWRegList({w10, w11, w12, w13});
  __ Pop(w14, w15, w16, w17);

  __ Claim(2);
  __ Push(w2, w2, w1, w1);
  __ Push(x3, x3);
  __ Pop(w30, w19, w20, w21);
  __ Pop(x22, x23);

  __ Claim(2);
  __ PushXRegList({x1, x22});
  __ PopXRegList({x24, x26});

  __ Claim(2);
  __ PushWRegList({w1, w2, w4, w22});
  __ PopWRegList({w25, w27, w28, w29});

  __ Claim(2);
  __ PushXRegList({});
  __ PopXRegList({});
  // Don't push/pop x18 (platform register) or lr
  RegList all_regs = RegList::FromBits(0xFFFFFFFF) - RegList{x18, lr};
  __ PushXRegList(all_regs);
  __ PopXRegList(all_regs);
  __ Drop(12);

  END();

  RUN();

  CHECK_EQUAL_64(0x1111111111111111UL, x3);
  CHECK_EQUAL_64(0x0000000000000000UL, x2);
  CHECK_EQUAL_64(0x3333333333333333UL, x1);
  CHECK_EQUAL_64(0x2222222222222222UL, x0);
  CHECK_EQUAL_64(0x3333333333333333UL, x9);
  CHECK_EQUAL_64(0x2222222222222222UL, x8);
  CHECK_EQUAL_64(0x0000000000000000UL, x7);
  CHECK_EQUAL_64(0x3333333333333333UL, x6);
  CHECK_EQUAL_64(0x1111111111111111UL, x5);
  CHECK_EQUAL_64(0x2222222222222222UL, x4);

  CHECK_EQUAL_32(0x11111111U, w13);
  CHECK_EQUAL_32(0x33333333U, w12);
  CHECK_EQUAL_32(0x00000000U, w11);
  CHECK_EQUAL_32(0x22222222U, w10);
  CHECK_EQUAL_32(0x11111111U, w17);
  CHECK_EQUAL_32(0x00000000U, w16);
  CHECK_EQUAL_32(0x33333333U, w15);
  CHECK_EQUAL_32(0x22222222U, w14);

  CHECK_EQUAL_32(0x11111111U, w30);
  CHECK_EQUAL_32(0x11111111U, w19);
  CHECK_EQUAL_32(0x11111111U, w20);
  CHECK_EQUAL_32(0x11111111U, w21);
  CHECK_EQUAL_64(0x3333333333333333UL, x22);
  CHECK_EQUAL_64(0x0000000000000000UL, x23);

  CHECK_EQUAL_64(0x3333333333333333UL, x24);
  CHECK_EQUAL_64(0x3333333333333333UL, x26);

  CHECK_EQUAL_32(0x33333333U, w25);
  CHECK_EQUAL_32(0x00000000U, w27);
  CHECK_EQUAL_32(0x22222222U, w28);
  CHECK_EQUAL_32(0x33333333U, w29);
}

TEST(copy_slots_down) {
  INIT_V8();
  SETUP();

  const uint64_t ones = 0x1111111111111111UL;
  const uint64_t twos = 0x2222222222222222UL;
  const uint64_t threes = 0x3333333333333333UL;
  const uint64_t fours = 0x4444444444444444UL;

  START();

  // Test copying 12 slots down one slot.
  __ Mov(x1, ones);
  __ Mov(x2, twos);
  __ Mov(x3, threes);
  __ Mov(x4, fours);

  __ Push(x1, x2, x3, x4);
  __ Push(x1, x2, x1, x2);
  __ Push(x3, x4, x3, x4);
  __ Push(xzr, xzr);

  __ Mov(x5, 1);
  __ Mov(x6, 2);
  __ Mov(x7, 12);
  __ CopySlots(x5, x6, x7);

  __ Pop(xzr, x4, x5, x6);
  __ Pop(x7, x8, x9, x10);
  __ Pop(x11, x12, x13, x14);
  __ Pop(x15, xzr);

  // Test copying one slot down one slot.
  __ Push(x1, xzr, xzr, xzr);

  __ Mov(x1, 2);
  __ Mov(x2, 3);
  __ Mov(x3, 1);
  __ CopySlots(x1, x2, x3);

  __ Drop(2);
  __ Pop(x0, xzr);

  END();

  RUN();

  CHECK_EQUAL_64(fours, x4);
  CHECK_EQUAL_64(threes, x5);
  CHECK_EQUAL_64(fours, x6);
  CHECK_EQUAL_64(threes, x7);

  CHECK_EQUAL_64(twos, x8);
  CHECK_EQUAL_64(ones, x9);
  CHECK_EQUAL_64(twos, x10);
  CHECK_EQUAL_64(ones, x11);

  CHECK_EQUAL_64(fours, x12);
  CHECK_EQUAL_64(threes, x13);
  CHECK_EQUAL_64(twos, x14);
  CHECK_EQUAL_64(ones, x15);

  CHECK_EQUAL_64(ones, x0);
}

TEST(copy_slots_up) {
  INIT_V8();
  SETUP();

  const uint64_t ones = 0x1111111111111111UL;
  const uint64_t twos = 0x2222222222222222UL;
  const uint64_t threes = 0x3333333333333333UL;

  START();

  __ Mov(x1, ones);
  __ Mov(x2, twos);
  __ Mov(x3, threes);

  // Test copying one slot to the next slot higher in memory.
  __ Push(xzr, x1);

  __ Mov(x5, 1);
  __ Mov(x6, 0);
  __ Mov(x7, 1);
  __ CopySlots(x5, x6, x7);

  __ Pop(xzr, x10);

  // Test copying two slots to the next two slots higher in memory.
  __ Push(xzr, xzr);
  __ Push(x1, x2);

  __ Mov(x5, 2);
  __ Mov(x6, 0);
  __ Mov(x7, 2);
  __ CopySlots(x5, x6, x7);

  __ Drop(2);
  __ Pop(x11, x12);

  // Test copying three slots to the next three slots higher in memory.
  __ Push(xzr, xzr, xzr, x1);
  __ Push(x2, x3);

  __ Mov(x5, 3);
  __ Mov(x6, 0);
  __ Mov(x7, 3);
  __ CopySlots(x5, x6, x7);

  __ Drop(2);
  __ Pop(xzr, x0, x1, x2);

  END();

  RUN();

  CHECK_EQUAL_64(ones, x10);
  CHECK_EQUAL_64(twos, x11);
  CHECK_EQUAL_64(ones, x12);
  CHECK_EQUAL_64(threes, x0);
  CHECK_EQUAL_64(twos, x1);
  CHECK_EQUAL_64(ones, x2);
}

TEST(copy_double_words_downwards_even) {
  INIT_V8();
  SETUP();

  const uint64_t ones = 0x1111111111111111UL;
  const uint64_t twos = 0x2222222222222222UL;
  const uint64_t threes = 0x3333333333333333UL;
  const uint64_t fours = 0x4444444444444444UL;

  START();

  // Test copying 12 slots up one slot.
  __ Mov(x1, ones);
  __ Mov(x2, twos);
  __ Mov(x3, threes);
  __ Mov(x4, fours);

  __ Push(xzr, xzr);
  __ Push(x1, x2, x3, x4);
  __ Push(x1, x2, x1, x2);
  __ Push(x3, x4, x3, x4);

  __ SlotAddress(x5, 12);
  __ SlotAddress(x6, 11);
  __ Mov(x7, 12);
  __ CopyDoubleWords(x5, x6, x7, MacroAssembler::kSrcLessThanDst);

  __ Pop(xzr, x4, x5, x6);
  __ Pop(x7, x8, x9, x10);
  __ Pop(x11, x12, x13, x14);
  __ Pop(x15, xzr);

  END();

  RUN();

  CHECK_EQUAL_64(ones, x15);
  CHECK_EQUAL_64(twos, x14);
  CHECK_EQUAL_64(threes, x13);
  CHECK_EQUAL_64(fours, x12);

  CHECK_EQUAL_64(ones, x11);
  CHECK_EQUAL_64(twos, x10);
  CHECK_EQUAL_64(ones, x9);
  CHECK_EQUAL_64(twos, x8);

  CHECK_EQUAL_64(threes, x7);
  CHECK_EQUAL_64(fours, x6);
  CHECK_EQUAL_64(threes, x5);
  CHECK_EQUAL_64(fours, x4);
}

TEST(copy_double_words_downwards_odd) {
  INIT_V8();
  SETUP();

  const uint64_t ones = 0x1111111111111111UL;
  const uint64_t twos = 0x2222222222222222UL;
  const uint64_t threes = 0x3333333333333333UL;
  const uint64_t fours = 0x4444444444444444UL;
  const uint64_t fives = 0x5555555555555555UL;

  START();

  // Test copying 13 slots up one slot.
  __ Mov(x1, ones);
  __ Mov(x2, twos);
  __ Mov(x3, threes);
  __ Mov(x4, fours);
  __ Mov(x5, fives);

  __ Push(xzr, x5);
  __ Push(x1, x2, x3, x4);
  __ Push(x1, x2, x1, x2);
  __ Push(x3, x4, x3, x4);

  __ SlotAddress(x5, 13);
  __ SlotAddress(x6, 12);
  __ Mov(x7, 13);
  __ CopyDoubleWords(x5, x6, x7, MacroAssembler::kSrcLessThanDst);

  __ Pop(xzr, x4);
  __ Pop(x5, x6, x7, x8);
  __ Pop(x9, x10, x11, x12);
  __ Pop(x13, x14, x15, x16);

  END();

  RUN();

  CHECK_EQUAL_64(fives, x16);

  CHECK_EQUAL_64(ones, x15);
  CHECK_EQUAL_64(twos, x14);
  CHECK_EQUAL_64(threes, x13);
  CHECK_EQUAL_64(fours, x12);

  CHECK_EQUAL_64(ones, x11);
  CHECK_EQUAL_64(twos, x10);
  CHECK_EQUAL_64(ones, x9);
  CHECK_EQUAL_64(twos, x8);

  CHECK_EQUAL_64(threes, x7);
  CHECK_EQUAL_64(fours, x6);
  CHECK_EQUAL_64(threes, x5);
  CHECK_EQUAL_64(fours, x4);
}

TEST(copy_noop) {
  INIT_V8();
  SETUP();

  const uint64_t ones = 0x1111111111111111UL;
  const uint64_t twos = 0x2222222222222222UL;
  const uint64_t threes = 0x3333333333333333UL;
  const uint64_t fours = 0x4444444444444444UL;
  const uint64_t fives = 0x5555555555555555UL;

  START();

  __ Mov(x1, ones);
  __ Mov(x2, twos);
  __ Mov(x3, threes);
  __ Mov(x4, fours);
  __ Mov(x5, fives);

  __ Push(xzr, x5, x5, xzr);
  __ Push(x3, x4, x3, x4);
  __ Push(x1, x2, x1, x2);
  __ Push(x1, x2, x3, x4);

  // src < dst, count == 0
  __ SlotAddress(x5, 3);
  __ SlotAddress(x6, 2);
  __ Mov(x7, 0);
  __ CopyDoubleWords(x5, x6, x7, MacroAssembler::kSrcLessThanDst);

  // dst < src, count == 0
  __ SlotAddress(x5, 2);
  __ SlotAddress(x6, 3);
  __ Mov(x7, 0);
  __ CopyDoubleWords(x5, x6, x7, MacroAssembler::kDstLessThanSrc);

  __ Pop(x1, x2, x3, x4);
  __ Pop(x5, x6, x7, x8);
  __ Pop(x9, x10, x11, x12);
  __ Pop(x13, x14, x15, x16);

  END();

  RUN();

  CHECK_EQUAL_64(fours, x1);
  CHECK_EQUAL_64(threes, x2);
  CHECK_EQUAL_64(twos, x3);
  CHECK_EQUAL_64(ones, x4);

  CHECK_EQUAL_64(twos, x5);
  CHECK_EQUAL_64(ones, x6);
  CHECK_EQUAL_64(twos, x7);
  CHECK_EQUAL_64(ones, x8);

  CHECK_EQUAL_64(fours, x9);
  CHECK_EQUAL_64(threes, x10);
  CHECK_EQUAL_64(fours, x11);
  CHECK_EQUAL_64(threes, x12);

  CHECK_EQUAL_64(0, x13);
  CHECK_EQUAL_64(fives, x14);
  CHECK_EQUAL_64(fives, x15);
  CHECK_EQUAL_64(0, x16);
}

TEST(noreg) {
  // This test doesn't generate any code, but it verifies some invariants
  // related to NoReg.
  CHECK_EQ(NoReg, NoVReg);
  CHECK_EQ(NoVReg, NoReg);
  CHECK_EQ(NoReg, NoCPUReg);
  CHECK_EQ(NoCPUReg, NoReg);
  CHECK_EQ(NoVReg, NoCPUReg);
  CHECK_EQ(NoCPUReg, NoVReg);

  CHECK(NoReg.IsNone());
  CHECK(NoVReg.IsNone());
  CHECK(NoCPUReg.IsNone());
}

TEST(vreg) {
  // This test doesn't generate any code, but it verifies
  // Helper functions and methods pertaining to VRegister logic.

  CHECK_EQ(8U, RegisterSizeInBitsFromFormat(kFormatB));
  CHECK_EQ(16U, RegisterSizeInBitsFromFormat(kFormatH));
  CHECK_EQ(32U, RegisterSizeInBitsFromFormat(kFormatS));
  CHECK_EQ(64U, RegisterSizeInBitsFromFormat(kFormatD));
  CHECK_EQ(64U, RegisterSizeInBitsFromFormat(kFormat8B));
  CHECK_EQ(64U, RegisterSizeInBitsFromFormat(kFormat4H));
  CHECK_EQ(64U, RegisterSizeInBitsFromFormat(kFormat2S));
  CHECK_EQ(64U, RegisterSizeInBitsFromFormat(kFormat1D));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat16B));
  CHECK_EQ(128U, RegisterSizeInBitsFromF
```