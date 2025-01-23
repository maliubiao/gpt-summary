Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a functional summary of the provided C++ code snippet, specifically from a V8 test file. They also ask about the context (Torque, JavaScript relation), code logic, common errors, and a high-level summary.

2. **Identify the File Type and Purpose:** The path `v8/test/cctest/test-assembler-arm64.cc` immediately tells me this is a C++ test file (`.cc`) for the V8 JavaScript engine. The "cctest" part suggests it's a component client test, likely focusing on low-level functionality. "assembler-arm64" indicates this test specifically exercises the ARM64 assembler within V8. This is crucial context.

3. **Scan for Key Elements:** I'll quickly scan the code for common test structures and patterns:
    * `TEST(...)`: This confirms it's a Google Test-based test file. Each `TEST` block represents an individual test case.
    * `INIT_V8(); SETUP(); START(); ... END(); RUN(); CHECK_EQUAL...`: This is a typical pattern for V8's test infrastructure, setting up the environment, defining the assembly code to test, running it, and verifying the results.
    * `MacroAssembler`: This class is central to generating machine code instructions. Seeing its usage is a strong indicator of the code's purpose.
    * Instruction mnemonics (e.g., `Mov`, `Add`, `Cmp`, `Lsl`, `Fmov`, etc.):  These are ARM64 assembly instructions, confirming the file's focus.
    * Expected values and flags (e.g., `CHECK_EQUAL_64`, `CHECK_EQUAL_NZCV`): This points to the tests verifying the correct behavior of assembler instructions, including how they affect processor flags.
    * Predefined constants (e.g., `kFP32PositiveInfinity`, `kFP64NegativeInfinity`): These indicate testing of floating-point operations.
    * Test names (e.g., `adc_sbc_flags`, `cmp_shift`, `fadd`): These provide hints about what each test case is exercising.

4. **Infer Functionality from Test Cases:** By looking at the test names and the instructions used within each `TEST` block, I can deduce the functionality being tested:
    * `adc_sbc_flags`: Tests the `Adc` (add with carry) and `Sbc` (subtract with carry) instructions and their effect on processor flags.
    * `adc_sbc_shift`, `adc_sbc_extend`, `adc_sbc_wide_imm`: Test `Adc` and `Sbc` with different operand types (shifted registers, extended registers, immediate values).
    * `flags`: Tests the setting and checking of processor flags.
    * `cmp_shift`, `cmp_extend`: Test the `Cmp` (compare) instruction with shifted and extended operands.
    * `ccmp`, `ccmp_wide_imm`, `ccmp_shift_extend`: Test the `Ccmp` (conditional compare) instruction.
    * `csel`, `csel_imm`: Test the `Csel` (conditional select) instruction.
    * `lslv`, `lsrv`, `asrv`, `rorv`: Test the variable shift instructions (logical shift left, logical shift right, arithmetic shift right, rotate right).
    * `bfm`, `sbfm`, `ubfm`: Test the bitfield manipulation instructions (bitfield move, signed bitfield move, unsigned bitfield move).
    * `extr`: Tests the `Extr` (extract register) instruction.
    * `fmov_imm`, `fmov_reg`: Tests the `Fmov` (floating-point move) instruction with immediate values and registers.
    * `fadd`: Tests the `Fadd` (floating-point add) instruction.

5. **Address Specific Questions:**

    * **Functionality Listing:** Based on the test cases, I can list the tested functionalities as various ARM64 assembler instructions related to arithmetic, logic, comparisons, conditional execution, and floating-point operations.
    * **Torque:** The filename ends in `.cc`, not `.tq`, so it's C++, not Torque.
    * **JavaScript Relation:**  While this is a low-level test, the instructions being tested are the *building blocks* for implementing JavaScript functionality in V8. I need to provide a relevant JavaScript example. Something simple like addition (`+`) would be a good fit, as the `Adc` instruction could be used internally to implement multi-precision addition if needed.
    * **Code Logic and Examples:** For `adc_sbc_flags`, I can illustrate the carry flag's role with simple examples of addition and subtraction that overflow or require borrowing. I'll provide example inputs and the expected output *based on the data provided in the test*.
    * **Common Programming Errors:**  I'll relate the tested instructions to common errors like integer overflow (relevant to `adc` and `sbc`) and incorrect flag checks in conditional logic (relevant to `cmp` and `ccmp`).
    * **Overall Function Summary:** I'll provide a concise summary stating that this file tests the correctness of V8's ARM64 assembler by verifying the behavior of various instructions and their effects on processor flags.

6. **Structure and Refine:** I'll organize the information clearly, addressing each part of the user's request. I'll use formatting (like bullet points and code blocks) to improve readability. I'll ensure the language is accurate and avoids jargon where possible, or explains it when necessary. I need to pay attention to the "part 8 of 15" and acknowledge that this is a subsection of a larger testing effort.

7. **Review and Verify:** Before submitting the answer, I'll reread it to make sure it's accurate, complete, and addresses all aspects of the request. I'll double-check the JavaScript example and the input/output examples for correctness.

By following these steps, I can generate a comprehensive and informative answer that addresses the user's request effectively. The key is to leverage the structure of the test file and the names of the test cases to understand the underlying functionality being verified.
好的，让我们来分析一下 `v8/test/cctest/test-assembler-arm64.cc` 这个文件的功能。

**文件功能归纳**

这个 C++ 文件是 V8 JavaScript 引擎的一部分，专门用于测试 ARM64 架构的汇编器（`Assembler`）。它的主要功能是：

1. **测试 ARM64 汇编指令的正确性：**  文件中包含了大量的测试用例（以 `TEST(...)` 宏定义），每个测试用例针对一个或一组 ARM64 汇编指令。这些测试用例会生成特定的汇编代码，执行这些代码，并验证执行结果（包括寄存器的值和处理器标志位）是否与预期一致。

2. **覆盖多种指令变体和操作数类型：** 测试用例覆盖了指令的不同变体（例如，带进位的加法 `Adc` 和不带进位的加法 `Add`），以及各种操作数类型（寄存器、立即数、移位寄存器、扩展寄存器等）。

3. **验证处理器标志位的影响：**  很多测试用例特别关注指令执行后处理器标志位（N, Z, C, V）的设置情况。这对于条件跳转、条件选择等指令的正确执行至关重要。

4. **作为 V8 汇编器开发和维护的保障：**  这些测试用例构成了一个回归测试套件。在修改或优化 V8 的汇编器代码后，可以运行这些测试用例来确保修改没有引入新的错误，并保持现有功能的正确性。

**关于文件类型和 JavaScript 关联**

* **`.tq` 结尾：**  该文件名为 `test-assembler-arm64.cc`，以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

* **与 JavaScript 的关系：**  虽然这个文件本身是 C++ 代码，并且直接操作的是底层的 ARM64 汇编指令，但它与 JavaScript 的功能有着密切的关系。V8 引擎需要将 JavaScript 代码编译成机器码才能在 CPU 上执行。`Assembler` 类负责生成这些机器码。因此，这个测试文件实际上是在测试 V8 将 JavaScript 代码最终转化为 ARM64 指令的正确性。

**JavaScript 示例**

尽管无法直接用 JavaScript 重现这个 C++ 测试文件的功能，但我们可以通过一些 JavaScript 操作来理解它所测试的底层汇编指令的作用。

例如，测试用例中有很多关于加法指令 (`Add`, `Adc`) 的测试。在 JavaScript 中执行简单的加法操作，最终 V8 可能会使用类似的汇编指令来实现：

```javascript
let a = 5;
let b = 10;
let sum = a + b;
console.log(sum); // 输出 15
```

在 V8 的内部，执行 `a + b` 这个操作时，可能会生成类似以下的 ARM64 汇编指令（简化示例）：

```assembly
MOV  W0, #5     ; 将立即数 5 移动到 W0 寄存器 (对应变量 a)
MOV  W1, #10    ; 将立即数 10 移动到 W1 寄存器 (对应变量 b)
ADD  W2, W0, W1  ; 将 W0 和 W1 的值相加，结果存储到 W2 寄存器 (对应变量 sum)
```

测试文件中的 `TEST(add_imm)` 等测试用例就是在验证 `ADD` 指令的行为是否符合预期。

**代码逻辑推理和示例**

让我们以 `TEST(adc_sbc_flags)` 中的一个测试数据为例：

```c++
{{0x00000000, ZFlag, 0x00000001, NoFlag}, ...}
```

这个数据对应的 `AdcsSbcsHelper` 函数调用会执行以下逻辑：

1. **假设输入：**
   - `left_input`: 0x00000000
   - `right_input`: 任意值（因为这里是测试 `Adcs` 的第一个变体，进位标志为 0）
   - `carry_in`: 0 (NoFlag 被映射为 0)

2. **汇编指令：** 执行 `Adcs` 指令，将 `left_input` 和 `right_input` 相加，并加上进位 `carry_in`。

3. **预期输出和标志位：**
   - `expected_result`: 0x00000001
   - `expected_flags`: `NoFlag` (表示 Z, N, C, V 标志位都不应该被设置，这里可能略有简化，实际情况会更复杂，需要考虑加法是否溢出等)

   **更准确的理解：**  `expected_flags`  指的是执行 `Adcs` *之后* 期望的标志位状态。在这个例子中，由于 0 + 任意数（假设加 1） + 0 = 1，结果非零，所以 Z 标志位不应设置。N 标志位也不应设置（结果为正数）。C 和 V 的设置取决于具体的 `right_input` 值，但在这个特定的测试用例中，预期是没有设置 C 标志位。

**用户常见的编程错误**

与这类底层汇编测试相关的用户常见编程错误通常发生在需要进行位操作或处理底层数据时。例如：

1. **整数溢出：**  在进行加法或乘法运算时，结果超出了数据类型的表示范围，导致数据丢失或产生意外的值。例如，在 JavaScript 中，数值类型是双精度浮点数，溢出的概念不太一样，但在处理 TypedArrays 等底层数据时可能会遇到类似问题。

   ```javascript
   let maxInt = 2147483647;
   let result = maxInt + 1; // 在某些情况下可能导致溢出，具体行为取决于环境
   ```

2. **位操作错误：**  在进行位移、按位与、按位或等操作时，可能会因为对操作符的理解不准确或移位位数错误而得到错误的结果。

   ```javascript
   let num = 10; // 二进制 1010
   let shifted = num << 2; // 左移 2 位，期望得到 40 (二进制 101000)
   ```
   如果对移位操作的理解有误，可能会得到错误的结果。

3. **对处理器标志位的误解：**  在编写与硬件交互的代码时，如果对处理器标志位的含义和影响不清楚，可能会导致条件判断错误或逻辑错误。虽然 JavaScript 开发者通常不需要直接操作标志位，但在某些底层库或 WebAssembly 代码中可能会遇到。

**第 8 部分功能归纳**

考虑到这是第 8 部分，并且之前的测试用例主要关注 `Adc` 和 `Sbc` 指令，我们可以推测这部分测试可能集中在：

* **`Adc`（带进位加法）和 `Sbc`（带借位减法）指令的各种操作数组合：**  例如，寄存器与寄存器、寄存器与立即数、寄存器与移位/扩展的寄存器等。
* **`Adc` 和 `Sbc` 指令对处理器标志位（特别是 C 标志位）的影响：**  验证在不同输入情况下，进位标志是否被正确设置。
* **可能涉及到 32 位和 64 位寄存器的操作：**  测试指令在不同位宽下的行为。

**总结**

`v8/test/cctest/test-assembler-arm64.cc` 的第 8 部分主要负责测试 V8 引擎在 ARM64 架构上执行带进位加法 (`Adc`) 和带借位减法 (`Sbc`) 汇编指令的正确性。它通过提供各种输入和预期输出来验证汇编器的实现是否符合 ARM64 指令集的规范，并确保这些指令能够正确地影响处理器标志位。这对于保证 V8 引擎在 ARM64 平台上的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
ZFlag, 0x00000001, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NFlag, 0x80000001, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag}},
      {{0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x00000002, NoFlag, 0x00000003, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag}},
      {{0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0xFFFFFFFC, NVFlag, 0xFFFFFFFD, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag}},
      {{0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFE, NVFlag, 0xFFFFFFFF, NVFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag}},
      {{0x80000000, NFlag, 0x80000001, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCVFlag, 0x00000001, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag}},
      {{0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000002, CVFlag, 0x00000003, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag}},
      {{0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0xFFFFFFFC, NCFlag, 0xFFFFFFFD, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag}},
      {{0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0xFFFFFFFE, NCFlag, 0xFFFFFFFF, NCFlag}}};

  static const Expected expected_sbcs_w[input_count][input_count] = {
      {{0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NFlag, 0x80000001, NFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag},
       {0x00000000, ZFlag, 0x00000001, NoFlag}},
      {{0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x00000002, NoFlag, 0x00000003, NoFlag},
       {0x00000001, NoFlag, 0x00000002, NoFlag}},
      {{0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0xFFFFFFFC, NVFlag, 0xFFFFFFFD, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag},
       {0x7FFFFFFE, NoFlag, 0x7FFFFFFF, NoFlag}},
      {{0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NVFlag, 0xFFFFFFFF, NVFlag},
       {0xFFFFFFFD, NVFlag, 0xFFFFFFFE, NVFlag},
       {0x80000000, NVFlag, 0x80000001, NVFlag},
       {0x7FFFFFFF, NoFlag, 0x80000000, NVFlag}},
      {{0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000000, ZCVFlag, 0x00000001, CVFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag},
       {0x80000000, NFlag, 0x80000001, NFlag}},
      {{0x80000000, NCFlag, 0x80000001, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x00000002, CVFlag, 0x00000003, CVFlag},
       {0x00000001, CVFlag, 0x00000002, CVFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0x80000002, NFlag, 0x80000003, NFlag},
       {0x80000001, NFlag, 0x80000002, NFlag}},
      {{0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0xFFFFFFFC, NCFlag, 0xFFFFFFFD, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CVFlag, 0x7FFFFFFF, CVFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x7FFFFFFC, CFlag, 0x7FFFFFFD, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag},
       {0xFFFFFFFE, NFlag, 0xFFFFFFFF, NFlag}},
      {{0xFFFFFFFE, NCFlag, 0xFFFFFFFF, NCFlag},
       {0xFFFFFFFD, NCFlag, 0xFFFFFFFE, NCFlag},
       {0x80000000, NCFlag, 0x80000001, NCFlag},
       {0x7FFFFFFF, CVFlag, 0x80000000, NCFlag},
       {0x7FFFFFFE, CFlag, 0x7FFFFFFF, CFlag},
       {0x7FFFFFFD, CFlag, 0x7FFFFFFE, CFlag},
       {0x00000000, ZCFlag, 0x00000001, CFlag},
       {0xFFFFFFFF, NFlag, 0x00000000, ZCFlag}}};

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_adcs_w[left][right];
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_sbcs_w[left][right];
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }
}

TEST(adc_sbc_shift) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x2, 0x0123456789ABCDEFL);
  __ Mov(x3, 0xFEDCBA9876543210L);
  __ Mov(x4, 0xFFFFFFFFFFFFFFFFL);

  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Adc(x5, x2, Operand(x3));
  __ Adc(x6, x0, Operand(x1, LSL, 60));
  __ Sbc(x7, x4, Operand(x3, LSR, 4));
  __ Adc(x8, x2, Operand(x3, ASR, 4));
  __ Adc(x9, x2, Operand(x3, ROR, 8));

  __ Adc(w10, w2, Operand(w3));
  __ Adc(w11, w0, Operand(w1, LSL, 30));
  __ Sbc(w12, w4, Operand(w3, LSR, 4));
  __ Adc(w13, w2, Operand(w3, ASR, 4));
  __ Adc(w14, w2, Operand(w3, ROR, 8));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x28, x2, Operand(x3));
  __ Adc(x19, x0, Operand(x1, LSL, 60));
  __ Sbc(x20, x4, Operand(x3, LSR, 4));
  __ Adc(x21, x2, Operand(x3, ASR, 4));
  __ Adc(x22, x2, Operand(x3, ROR, 8));

  __ Adc(w23, w2, Operand(w3));
  __ Adc(w24, w0, Operand(w1, LSL, 30));
  __ Sbc(w25, w4, Operand(w3, LSR, 4));
  __ Adc(w26, w2, Operand(w3, ASR, 4));
  __ Adc(w27, w2, Operand(w3, ROR, 8));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x5);
  CHECK_EQUAL_64(1LL << 60, x6);
  CHECK_EQUAL_64(0xF0123456789ABCDDL, x7);
  CHECK_EQUAL_64(0x0111111111111110L, x8);
  CHECK_EQUAL_64(0x1222222222222221L, x9);

  CHECK_EQUAL_32(0xFFFFFFFF, w10);
  CHECK_EQUAL_32(1 << 30, w11);
  CHECK_EQUAL_32(0xF89ABCDD, w12);
  CHECK_EQUAL_32(0x91111110, w13);
  CHECK_EQUAL_32(0x9A222221, w14);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFLL + 1, x28);
  CHECK_EQUAL_64((1LL << 60) + 1, x19);
  CHECK_EQUAL_64(0xF0123456789ABCDDL + 1, x20);
  CHECK_EQUAL_64(0x0111111111111110L + 1, x21);
  CHECK_EQUAL_64(0x1222222222222221L + 1, x22);

  CHECK_EQUAL_32(0xFFFFFFFFULL + 1, w23);
  CHECK_EQUAL_32((1 << 30) + 1, w24);
  CHECK_EQUAL_32(0xF89ABCDD + 1, w25);
  CHECK_EQUAL_32(0x91111110 + 1, w26);
  CHECK_EQUAL_32(0x9A222221 + 1, w27);
}

TEST(adc_sbc_extend) {
  INIT_V8();
  SETUP();

  START();
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x2, 0x0123456789ABCDEFL);

  __ Adc(x10, x1, Operand(w2, UXTB, 1));
  __ Adc(x11, x1, Operand(x2, SXTH, 2));
  __ Sbc(x12, x1, Operand(w2, UXTW, 4));
  __ Adc(x13, x1, Operand(x2, UXTX, 4));

  __ Adc(w14, w1, Operand(w2, UXTB, 1));
  __ Adc(w15, w1, Operand(w2, SXTH, 2));
  __ Adc(w9, w1, Operand(w2, UXTW, 4));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x20, x1, Operand(w2, UXTB, 1));
  __ Adc(x21, x1, Operand(x2, SXTH, 2));
  __ Sbc(x22, x1, Operand(w2, UXTW, 4));
  __ Adc(x23, x1, Operand(x2, UXTX, 4));

  __ Adc(w24, w1, Operand(w2, UXTB, 1));
  __ Adc(w25, w1, Operand(w2, SXTH, 2));
  __ Adc(w26, w1, Operand(w2, UXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0x1DF, x10);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BDL, x11);
  CHECK_EQUAL_64(0xFFFFFFF765432110L, x12);
  CHECK_EQUAL_64(0x123456789ABCDEF1L, x13);

  CHECK_EQUAL_32(0x1DF, w14);
  CHECK_EQUAL_32(0xFFFF37BD, w15);
  CHECK_EQUAL_32(0x9ABCDEF1, w9);

  CHECK_EQUAL_64(0x1DF + 1, x20);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BDL + 1, x21);
  CHECK_EQUAL_64(0xFFFFFFF765432110L + 1, x22);
  CHECK_EQUAL_64(0x123456789ABCDEF1L + 1, x23);

  CHECK_EQUAL_32(0x1DF + 1, w24);
  CHECK_EQUAL_32(0xFFFF37BD + 1, w25);
  CHECK_EQUAL_32(0x9ABCDEF1 + 1, w26);

  // Check that adc correctly sets the condition flags.
  START();
  __ Mov(x0, 0xFF);
  __ Mov(x1, 0xFFFFFFFFFFFFFFFFL);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(x1, SXTX, 1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(x0, 0x7FFFFFFFFFFFFFFFL);
  __ Mov(x1, 1);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(x1, UXTB, 2));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(x0, 0x7FFFFFFFFFFFFFFFL);
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Adcs(x10, x0, Operand(1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);
}

TEST(adc_sbc_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);

  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));

  __ Adc(x7, x0, Operand(0x1234567890ABCDEFUL));
  __ Adc(w8, w0, Operand(0xFFFFFFFF));
  __ Sbc(x9, x0, Operand(0x1234567890ABCDEFUL));
  __ Sbc(w10, w0, Operand(0xFFFFFFFF));
  __ Ngc(x11, Operand(0xFFFFFFFF00000000UL));
  __ Ngc(w12, Operand(0xFFFF0000));

  // Set the C flag.
  __ Cmp(w0, Operand(w0));

  __ Adc(x28, x0, Operand(0x1234567890ABCDEFUL));
  __ Adc(w19, w0, Operand(0xFFFFFFFF));
  __ Sbc(x20, x0, Operand(0x1234567890ABCDEFUL));
  __ Sbc(w21, w0, Operand(0xFFFFFFFF));
  __ Ngc(x22, Operand(0xFFFFFFFF00000000UL));
  __ Ngc(w23, Operand(0xFFFF0000));
  END();

  RUN();

  CHECK_EQUAL_64(0x1234567890ABCDEFUL, x7);
  CHECK_EQUAL_64(0xFFFFFFFF, x8);
  CHECK_EQUAL_64(0xEDCBA9876F543210UL, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(0xFFFFFFFF, x11);
  CHECK_EQUAL_64(0xFFFF, x12);

  CHECK_EQUAL_64(0x1234567890ABCDEFUL + 1, x28);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0xEDCBA9876F543211UL, x20);
  CHECK_EQUAL_64(1, x21);
  CHECK_EQUAL_64(0x100000000UL, x22);
  CHECK_EQUAL_64(0x10000, x23);
}

TEST(flags) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x1111111111111111L);
  __ Neg(x10, Operand(x0));
  __ Neg(x11, Operand(x1));
  __ Neg(w12, Operand(w1));
  // Clear the C flag.
  __ Adds(x0, x0, Operand(0));
  __ Ngc(x13, Operand(x0));
  // Set the C flag.
  __ Cmp(x0, Operand(x0));
  __ Ngc(w14, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(-0x1111111111111111L, x11);
  CHECK_EQUAL_32(-0x11111111, w12);
  CHECK_EQUAL_64(-1L, x13);
  CHECK_EQUAL_32(0, w14);

  START();
  __ Mov(x0, 0);
  __ Cmp(x0, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 0);
  __ Cmp(w0, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x1111111111111111L);
  __ Cmp(x0, Operand(x1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 0x11111111);
  __ Cmp(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(x1, 0x1111111111111111L);
  __ Cmp(x1, Operand(0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(w1, 0x11111111);
  __ Cmp(w1, Operand(0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(CFlag);

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0x7FFFFFFFFFFFFFFFL);
  __ Cmn(x1, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(w0, 1);
  __ Mov(w1, 0x7FFFFFFF);
  __ Cmn(w1, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NVFlag);

  START();
  __ Mov(x0, 1);
  __ Mov(x1, 0xFFFFFFFFFFFFFFFFL);
  __ Cmn(x1, Operand(x0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 1);
  __ Mov(w1, 0xFFFFFFFF);
  __ Cmn(w1, Operand(w0));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 1);
  // Clear the C flag.
  __ Adds(w0, w0, Operand(0));
  __ Ngcs(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(NFlag);

  START();
  __ Mov(w0, 0);
  __ Mov(w1, 0);
  // Set the C flag.
  __ Cmp(w0, Operand(w0));
  __ Ngcs(w0, Operand(w1));
  END();

  RUN();

  CHECK_EQUAL_NZCV(ZCFlag);
}

TEST(cmp_shift) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x28, 0xF0000000);
  __ Mov(x19, 0xF000000010000000UL);
  __ Mov(x20, 0xF0000000F0000000UL);
  __ Mov(x21, 0x7800000078000000UL);
  __ Mov(x22, 0x3C0000003C000000UL);
  __ Mov(x23, 0x8000000780000000UL);
  __ Mov(x24, 0x0000000F00000000UL);
  __ Mov(x25, 0x00000003C0000000UL);
  __ Mov(x26, 0x8000000780000000UL);
  __ Mov(x27, 0xC0000003);

  __ Cmp(w20, Operand(w21, LSL, 1));
  __ Mrs(x0, NZCV);

  __ Cmp(x20, Operand(x22, LSL, 2));
  __ Mrs(x1, NZCV);

  __ Cmp(w19, Operand(w23, LSR, 3));
  __ Mrs(x2, NZCV);

  __ Cmp(x28, Operand(x24, LSR, 4));
  __ Mrs(x3, NZCV);

  __ Cmp(w20, Operand(w25, ASR, 2));
  __ Mrs(x4, NZCV);

  __ Cmp(x20, Operand(x26, ASR, 3));
  __ Mrs(x5, NZCV);

  __ Cmp(w27, Operand(w22, ROR, 28));
  __ Mrs(x6, NZCV);

  __ Cmp(x20, Operand(x21, ROR, 31));
  __ Mrs(x7, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(ZCFlag, w3);
  CHECK_EQUAL_32(ZCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
  CHECK_EQUAL_32(ZCFlag, w6);
  CHECK_EQUAL_32(ZCFlag, w7);
}

TEST(cmp_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0x2);
  __ Mov(w21, 0x1);
  __ Mov(x22, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x23, 0xFF);
  __ Mov(x24, 0xFFFFFFFFFFFFFFFEUL);
  __ Mov(x25, 0xFFFF);
  __ Mov(x26, 0xFFFFFFFF);

  __ Cmp(w20, Operand(w21, LSL, 1));
  __ Mrs(x0, NZCV);

  __ Cmp(x22, Operand(x23, SXTB, 0));
  __ Mrs(x1, NZCV);

  __ Cmp(x24, Operand(x23, SXTB, 1));
  __ Mrs(x2, NZCV);

  __ Cmp(x24, Operand(x23, UXTB, 1));
  __ Mrs(x3, NZCV);

  __ Cmp(w22, Operand(w25, UXTH));
  __ Mrs(x4, NZCV);

  __ Cmp(x22, Operand(x25, SXTH));
  __ Mrs(x5, NZCV);

  __ Cmp(x22, Operand(x26, UXTW));
  __ Mrs(x6, NZCV);

  __ Cmp(x24, Operand(x26, SXTW, 1));
  __ Mrs(x7, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(NCFlag, w3);
  CHECK_EQUAL_32(NCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
  CHECK_EQUAL_32(NCFlag, w6);
  CHECK_EQUAL_32(ZCFlag, w7);
}

TEST(ccmp) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w16, 0);
  __ Mov(w17, 1);
  __ Cmp(w16, w16);
  __ Ccmp(w16, w17, NCFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w16, w16);
  __ Ccmp(w16, w17, NCFlag, ne);
  __ Mrs(x1, NZCV);

  __ Cmp(x16, x16);
  __ Ccmn(x16, 2, NZCVFlag, eq);
  __ Mrs(x2, NZCV);

  __ Cmp(x16, x16);
  __ Ccmn(x16, 2, NZCVFlag, ne);
  __ Mrs(x3, NZCV);

  __ ccmp(x16, x16, NZCVFlag, al);
  __ Mrs(x4, NZCV);

  __ ccmp(x16, x16, NZCVFlag, nv);
  __ Mrs(x5, NZCV);

  END();

  RUN();

  CHECK_EQUAL_32(NFlag, w0);
  CHECK_EQUAL_32(NCFlag, w1);
  CHECK_EQUAL_32(NoFlag, w2);
  CHECK_EQUAL_32(NZCVFlag, w3);
  CHECK_EQUAL_32(ZCFlag, w4);
  CHECK_EQUAL_32(ZCFlag, w5);
}

TEST(ccmp_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(w20, Operand(0x12345678), NZCVFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x20, Operand(0xFFFFFFFFFFFFFFFFUL), NZCVFlag, eq);
  __ Mrs(x1, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(NFlag, w0);
  CHECK_EQUAL_32(NoFlag, w1);
}

TEST(ccmp_shift_extend) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(w20, 0x2);
  __ Mov(w21, 0x1);
  __ Mov(x22, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x23, 0xFF);
  __ Mov(x24, 0xFFFFFFFFFFFFFFFEUL);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(w20, Operand(w21, LSL, 1), NZCVFlag, eq);
  __ Mrs(x0, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x22, Operand(x23, SXTB, 0), NZCVFlag, eq);
  __ Mrs(x1, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, SXTB, 1), NZCVFlag, eq);
  __ Mrs(x2, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, UXTB, 1), NZCVFlag, eq);
  __ Mrs(x3, NZCV);

  __ Cmp(w20, Operand(w20));
  __ Ccmp(x24, Operand(x23, UXTB, 1), NZCVFlag, ne);
  __ Mrs(x4, NZCV);
  END();

  RUN();

  CHECK_EQUAL_32(ZCFlag, w0);
  CHECK_EQUAL_32(ZCFlag, w1);
  CHECK_EQUAL_32(ZCFlag, w2);
  CHECK_EQUAL_32(NCFlag, w3);
  CHECK_EQUAL_32(NZCVFlag, w4);
}

TEST(csel) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x24, 0x0000000F0000000FUL);
  __ Mov(x25, 0x0000001F0000001FUL);
  __ Mov(x26, 0);
  __ Mov(x27, 0);

  __ Cmp(w16, 0);
  __ Csel(w0, w24, w25, eq);
  __ Csel(w1, w24, w25, ne);
  __ Csinc(w2, w24, w25, mi);
  __ Csinc(w3, w24, w25, pl);

  __ csel(w13, w24, w25, al);
  __ csel(x14, x24, x25, nv);

  __ Cmp(x16, 1);
  __ Csinv(x4, x24, x25, gt);
  __ Csinv(x5, x24, x25, le);
  __ Csneg(x6, x24, x25, hs);
  __ Csneg(x7, x24, x25, lo);

  __ Cset(w8, ne);
  __ Csetm(w9, ne);
  __ Cinc(x10, x25, ne);
  __ Cinv(x11, x24, ne);
  __ Cneg(x12, x24, ne);

  __ csel(w15, w24, w25, al);
  __ csel(x28, x24, x25, nv);

  __ CzeroX(x24, ne);
  __ CzeroX(x25, eq);

  __ CmovX(x26, x25, ne);
  __ CmovX(x27, x25, eq);
  END();

  RUN();

  CHECK_EQUAL_64(0x0000000F, x0);
  CHECK_EQUAL_64(0x0000001F, x1);
  CHECK_EQUAL_64(0x00000020, x2);
  CHECK_EQUAL_64(0x0000000F, x3);
  CHECK_EQUAL_64(0xFFFFFFE0FFFFFFE0UL, x4);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x5);
  CHECK_EQUAL_64(0xFFFFFFE0FFFFFFE1UL, x6);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x7);
  CHECK_EQUAL_64(0x00000001, x8);
  CHECK_EQUAL_64(0xFFFFFFFF, x9);
  CHECK_EQUAL_64(0x0000001F00000020UL, x10);
  CHECK_EQUAL_64(0xFFFFFFF0FFFFFFF0UL, x11);
  CHECK_EQUAL_64(0xFFFFFFF0FFFFFFF1UL, x12);
  CHECK_EQUAL_64(0x0000000F, x13);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x14);
  CHECK_EQUAL_64(0x0000000F, x15);
  CHECK_EQUAL_64(0x0000000F0000000FUL, x28);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x0000001F0000001FUL, x25);
  CHECK_EQUAL_64(0x0000001F0000001FUL, x26);
  CHECK_EQUAL_64(0, x27);
}

TEST(csel_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x28, 0);
  __ Mov(x19, 0x80000000);
  __ Mov(x20, 0x8000000000000000UL);

  __ Cmp(x28, Operand(0));
  __ Csel(w0, w19, -2, ne);
  __ Csel(w1, w19, -1, ne);
  __ Csel(w2, w19, 0, ne);
  __ Csel(w3, w19, 1, ne);
  __ Csel(w4, w19, 2, ne);
  __ Csel(w5, w19, Operand(w19, ASR, 31), ne);
  __ Csel(w6, w19, Operand(w19, ROR, 1), ne);
  __ Csel(w7, w19, 3, eq);

  __ Csel(x8, x20, -2, ne);
  __ Csel(x9, x20, -1, ne);
  __ Csel(x10, x20, 0, ne);
  __ Csel(x11, x20, 1, ne);
  __ Csel(x12, x20, 2, ne);
  __ Csel(x13, x20, Operand(x20, ASR, 63), ne);
  __ Csel(x14, x20, Operand(x20, ROR, 1), ne);
  __ Csel(x15, x20, 3, eq);

  END();

  RUN();

  CHECK_EQUAL_32(-2, w0);
  CHECK_EQUAL_32(-1, w1);
  CHECK_EQUAL_32(0, w2);
  CHECK_EQUAL_32(1, w3);
  CHECK_EQUAL_32(2, w4);
  CHECK_EQUAL_32(-1, w5);
  CHECK_EQUAL_32(0x40000000, w6);
  CHECK_EQUAL_32(0x80000000, w7);

  CHECK_EQUAL_64(-2, x8);
  CHECK_EQUAL_64(-1, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(1, x11);
  CHECK_EQUAL_64(2, x12);
  CHECK_EQUAL_64(-1, x13);
  CHECK_EQUAL_64(0x4000000000000000UL, x14);
  CHECK_EQUAL_64(0x8000000000000000UL, x15);
}

TEST(lslv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ lslv(x0, x0, xzr);

  __ Lsl(x16, x0, x1);
  __ Lsl(x17, x0, x2);
  __ Lsl(x28, x0, x3);
  __ Lsl(x19, x0, x4);
  __ Lsl(x20, x0, x5);
  __ Lsl(x21, x0, x6);

  __ Lsl(w22, w0, w1);
  __ Lsl(w23, w0, w2);
  __ Lsl(w24, w0, w3);
  __ Lsl(w25, w0, w4);
  __ Lsl(w26, w0, w5);
  __ Lsl(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value << (shift[0] & 63), x16);
  CHECK_EQUAL_64(value << (shift[1] & 63), x17);
  CHECK_EQUAL_64(value << (shift[2] & 63), x28);
  CHECK_EQUAL_64(value << (shift[3] & 63), x19);
  CHECK_EQUAL_64(value << (shift[4] & 63), x20);
  CHECK_EQUAL_64(value << (shift[5] & 63), x21);
  CHECK_EQUAL_32(value << (shift[0] & 31), w22);
  CHECK_EQUAL_32(value << (shift[1] & 31), w23);
  CHECK_EQUAL_32(value << (shift[2] & 31), w24);
  CHECK_EQUAL_32(value << (shift[3] & 31), w25);
  CHECK_EQUAL_32(value << (shift[4] & 31), w26);
  CHECK_EQUAL_32(value << (shift[5] & 31), w27);
}

TEST(lsrv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ lsrv(x0, x0, xzr);

  __ Lsr(x16, x0, x1);
  __ Lsr(x17, x0, x2);
  __ Lsr(x28, x0, x3);
  __ Lsr(x19, x0, x4);
  __ Lsr(x20, x0, x5);
  __ Lsr(x21, x0, x6);

  __ Lsr(w22, w0, w1);
  __ Lsr(w23, w0, w2);
  __ Lsr(w24, w0, w3);
  __ Lsr(w25, w0, w4);
  __ Lsr(w26, w0, w5);
  __ Lsr(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value >> (shift[0] & 63), x16);
  CHECK_EQUAL_64(value >> (shift[1] & 63), x17);
  CHECK_EQUAL_64(value >> (shift[2] & 63), x28);
  CHECK_EQUAL_64(value >> (shift[3] & 63), x19);
  CHECK_EQUAL_64(value >> (shift[4] & 63), x20);
  CHECK_EQUAL_64(value >> (shift[5] & 63), x21);

  value &= 0xFFFFFFFFUL;
  CHECK_EQUAL_32(value >> (shift[0] & 31), w22);
  CHECK_EQUAL_32(value >> (shift[1] & 31), w23);
  CHECK_EQUAL_32(value >> (shift[2] & 31), w24);
  CHECK_EQUAL_32(value >> (shift[3] & 31), w25);
  CHECK_EQUAL_32(value >> (shift[4] & 31), w26);
  CHECK_EQUAL_32(value >> (shift[5] & 31), w27);
}

TEST(asrv) {
  INIT_V8();
  SETUP();

  int64_t value = 0xFEDCBA98FEDCBA98UL;
  int shift[] = {1, 3, 5, 9, 17, 33};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ asrv(x0, x0, xzr);

  __ Asr(x16, x0, x1);
  __ Asr(x17, x0, x2);
  __ Asr(x28, x0, x3);
  __ Asr(x19, x0, x4);
  __ Asr(x20, x0, x5);
  __ Asr(x21, x0, x6);

  __ Asr(w22, w0, w1);
  __ Asr(w23, w0, w2);
  __ Asr(w24, w0, w3);
  __ Asr(w25, w0, w4);
  __ Asr(w26, w0, w5);
  __ Asr(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(value >> (shift[0] & 63), x16);
  CHECK_EQUAL_64(value >> (shift[1] & 63), x17);
  CHECK_EQUAL_64(value >> (shift[2] & 63), x28);
  CHECK_EQUAL_64(value >> (shift[3] & 63), x19);
  CHECK_EQUAL_64(value >> (shift[4] & 63), x20);
  CHECK_EQUAL_64(value >> (shift[5] & 63), x21);

  int32_t value32 = static_cast<int32_t>(value & 0xFFFFFFFFUL);
  CHECK_EQUAL_32(value32 >> (shift[0] & 31), w22);
  CHECK_EQUAL_32(value32 >> (shift[1] & 31), w23);
  CHECK_EQUAL_32(value32 >> (shift[2] & 31), w24);
  CHECK_EQUAL_32(value32 >> (shift[3] & 31), w25);
  CHECK_EQUAL_32(value32 >> (shift[4] & 31), w26);
  CHECK_EQUAL_32(value32 >> (shift[5] & 31), w27);
}

TEST(rorv) {
  INIT_V8();
  SETUP();

  uint64_t value = 0x0123456789ABCDEFUL;
  int shift[] = {4, 8, 12, 16, 24, 36};

  START();
  __ Mov(x0, value);
  __ Mov(w1, shift[0]);
  __ Mov(w2, shift[1]);
  __ Mov(w3, shift[2]);
  __ Mov(w4, shift[3]);
  __ Mov(w5, shift[4]);
  __ Mov(w6, shift[5]);

  __ rorv(x0, x0, xzr);

  __ Ror(x16, x0, x1);
  __ Ror(x17, x0, x2);
  __ Ror(x28, x0, x3);
  __ Ror(x19, x0, x4);
  __ Ror(x20, x0, x5);
  __ Ror(x21, x0, x6);

  __ Ror(w22, w0, w1);
  __ Ror(w23, w0, w2);
  __ Ror(w24, w0, w3);
  __ Ror(w25, w0, w4);
  __ Ror(w26, w0, w5);
  __ Ror(w27, w0, w6);
  END();

  RUN();

  CHECK_EQUAL_64(value, x0);
  CHECK_EQUAL_64(0xF0123456789ABCDEUL, x16);
  CHECK_EQUAL_64(0xEF0123456789ABCDUL, x17);
  CHECK_EQUAL_64(0xDEF0123456789ABCUL, x28);
  CHECK_EQUAL_64(0xCDEF0123456789ABUL, x19);
  CHECK_EQUAL_64(0xABCDEF0123456789UL, x20);
  CHECK_EQUAL_64(0x789ABCDEF0123456UL, x21);
  CHECK_EQUAL_32(0xF89ABCDE, w22);
  CHECK_EQUAL_32(0xEF89ABCD, w23);
  CHECK_EQUAL_32(0xDEF89ABC, w24);
  CHECK_EQUAL_32(0xCDEF89AB, w25);
  CHECK_EQUAL_32(0xABCDEF89, w26);
  CHECK_EQUAL_32(0xF89ABCDE, w27);
}

TEST(bfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);

  __ Mov(x10, 0x8888888888888888L);
  __ Mov(x11, 0x8888888888888888L);
  __ Mov(x12, 0x8888888888888888L);
  __ Mov(x13, 0x8888888888888888L);
  __ Mov(w20, 0x88888888);
  __ Mov(w21, 0x88888888);

  __ bfm(x10, x1, 16, 31);
  __ bfm(x11, x1, 32, 15);

  __ bfm(w20, w1, 16, 23);
  __ bfm(w21, w1, 24, 15);

  // Aliases.
  __ Bfi(x12, x1, 16, 8);
  __ Bfxil(x13, x1, 16, 8);
  END();

  RUN();

  CHECK_EQUAL_64(0x88888888888889ABL, x10);
  CHECK_EQUAL_64(0x8888CDEF88888888L, x11);

  CHECK_EQUAL_32(0x888888AB, w20);
  CHECK_EQUAL_32(0x88CDEF88, w21);

  CHECK_EQUAL_64(0x8888888888EF8888L, x12);
  CHECK_EQUAL_64(0x88888888888888ABL, x13);
}

TEST(sbfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ sbfm(x10, x1, 16, 31);
  __ sbfm(x11, x1, 32, 15);
  __ sbfm(x12, x1, 32, 47);
  __ sbfm(x13, x1, 48, 35);

  __ sbfm(w14, w1, 16, 23);
  __ sbfm(w15, w1, 24, 15);
  __ sbfm(w16, w2, 16, 23);
  __ sbfm(w17, w2, 24, 15);

  // Aliases.
  __ Asr(x3, x1, 32);
  __ Asr(x19, x2, 32);
  __ Sbfiz(x20, x1, 8, 16);
  __ Sbfiz(x21, x2, 8, 16);
  __ Sbfx(x22, x1, 8, 16);
  __ Sbfx(x23, x2, 8, 16);
  __ Sxtb(x24, w1);
  __ Sxtb(x25, x2);
  __ Sxth(x26, w1);
  __ Sxth(x27, x2);
  __ Sxtw(x28, w1);
  __ Sxtw(x29, x2);
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFF89ABL, x10);
  CHECK_EQUAL_64(0xFFFFCDEF00000000L, x11);
  CHECK_EQUAL_64(0x4567L, x12);
  CHECK_EQUAL_64(0x789ABCDEF0000L, x13);

  CHECK_EQUAL_32(0xFFFFFFAB, w14);
  CHECK_EQUAL_32(0xFFCDEF00, w15);
  CHECK_EQUAL_32(0x54, w16);
  CHECK_EQUAL_32(0x00321000, w17);

  CHECK_EQUAL_64(0x01234567L, x3);
  CHECK_EQUAL_64(0xFFFFFFFFFEDCBA98L, x19);
  CHECK_EQUAL_64(0xFFFFFFFFFFCDEF00L, x20);
  CHECK_EQUAL_64(0x321000L, x21);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFABCDL, x22);
  CHECK_EQUAL_64(0x5432L, x23);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFEFL, x24);
  CHECK_EQUAL_64(0x10, x25);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFCDEFL, x26);
  CHECK_EQUAL_64(0x3210, x27);
  CHECK_EQUAL_64(0xFFFFFFFF89ABCDEFL, x28);
  CHECK_EQUAL_64(0x76543210, x29);
}

TEST(ubfm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ Mov(x10, 0x8888888888888888L);
  __ Mov(x11, 0x8888888888888888L);

  __ ubfm(x10, x1, 16, 31);
  __ ubfm(x11, x1, 32, 15);
  __ ubfm(x12, x1, 32, 47);
  __ ubfm(x13, x1, 48, 35);

  __ ubfm(w25, w1, 16, 23);
  __ ubfm(w26, w1, 24, 15);
  __ ubfm(w27, w2, 16, 23);
  __ ubfm(w28, w2, 24, 15);

  // Aliases
  __ Lsl(x15, x1, 63);
  __ Lsl(x16, x1, 0);
  __ Lsr(x17, x1, 32);
  __ Ubfiz(x3, x1, 8, 16);
  __ Ubfx(x19, x1, 8, 16);
  __ Uxtb(x20, x1);
  __ Uxth(x21, x1);
  __ Uxtw(x22, x1);
  END();

  RUN();

  CHECK_EQUAL_64(0x00000000000089ABL, x10);
  CHECK_EQUAL_64(0x0000CDEF00000000L, x11);
  CHECK_EQUAL_64(0x4567L, x12);
  CHECK_EQUAL_64(0x789ABCDEF0000L, x13);

  CHECK_EQUAL_32(0x000000AB, w25);
  CHECK_EQUAL_32(0x00CDEF00, w26);
  CHECK_EQUAL_32(0x54, w27);
  CHECK_EQUAL_32(0x00321000, w28);

  CHECK_EQUAL_64(0x8000000000000000L, x15);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x16);
  CHECK_EQUAL_64(0x01234567L, x17);
  CHECK_EQUAL_64(0xCDEF00L, x3);
  CHECK_EQUAL_64(0xABCDL, x19);
  CHECK_EQUAL_64(0xEFL, x20);
  CHECK_EQUAL_64(0xCDEFL, x21);
  CHECK_EQUAL_64(0x89ABCDEFL, x22);
}

TEST(extr) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);

  __ Extr(w10, w1, w2, 0);
  __ Extr(x11, x1, x2, 0);
  __ Extr(w12, w1, w2, 1);
  __ Extr(x13, x2, x1, 2);

  __ Ror(w20, w1, 0);
  __ Ror(x21, x1, 0);
  __ Ror(w22, w2, 17);
  __ Ror(w23, w1, 31);
  __ Ror(x24, x2, 1);
  __ Ror(x25, x1, 63);
  END();

  RUN();

  CHECK_EQUAL_64(0x76543210, x10);
  CHECK_EQUAL_64(0xFEDCBA9876543210L, x11);
  CHECK_EQUAL_64(0xBB2A1908, x12);
  CHECK_EQUAL_64(0x0048D159E26AF37BUL, x13);
  CHECK_EQUAL_64(0x89ABCDEF, x20);
  CHECK_EQUAL_64(0x0123456789ABCDEFL, x21);
  CHECK_EQUAL_64(0x19083B2A, x22);
  CHECK_EQUAL_64(0x13579BDF, x23);
  CHECK_EQUAL_64(0x7F6E5D4C3B2A1908UL, x24);
  CHECK_EQUAL_64(0x02468ACF13579BDEUL, x25);
}

TEST(fmov_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s11, 1.0);
  __ Fmov(d22, -13.0);
  __ Fmov(s1, 255.0);
  __ Fmov(d2, 12.34567);
  __ Fmov(s3, 0.0);
  __ Fmov(d4, 0.0);
  __ Fmov(s5, kFP32PositiveInfinity);
  __ Fmov(d6, kFP64NegativeInfinity);
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s11);
  CHECK_EQUAL_FP64(-13.0, d22);
  CHECK_EQUAL_FP32(255.0, s1);
  CHECK_EQUAL_FP64(12.34567, d2);
  CHECK_EQUAL_FP32(0.0, s3);
  CHECK_EQUAL_FP64(0.0, d4);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s5);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d6);
}

TEST(fmov_reg) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s20, 1.0);
  __ Fmov(w10, s20);
  __ Fmov(s30, w10);
  __ Fmov(s5, s20);
  __ Fmov(d1, -13.0);
  __ Fmov(x1, d1);
  __ Fmov(d2, x1);
  __ Fmov(d4, d1);
  __ Fmov(d6, base::bit_cast<double>(0x0123456789ABCDEFL));
  __ Fmov(s6, s6);
  END();

  RUN();

  CHECK_EQUAL_32(base::bit_cast<uint32_t>(1.0f), w10);
  CHECK_EQUAL_FP32(1.0, s30);
  CHECK_EQUAL_FP32(1.0, s5);
  CHECK_EQUAL_64(base::bit_cast<uint64_t>(-13.0), x1);
  CHECK_EQUAL_FP64(-13.0, d2);
  CHECK_EQUAL_FP64(-13.0, d4);
  CHECK_EQUAL_FP32(base::bit_cast<float>(0x89ABCDEF), s6);
}

TEST(fadd) {
  INIT_V8();
  SETUP();

  START();
  __ Fmov(s14, -0.0f);
  __ Fmov(s15, kFP32PositiveInfinity);
  __ Fmov(s16, kFP32NegativeInfinity);
  __ Fmov(s17, 3.25f);
  __ Fmov(s18, 1.0f);
  __ Fmov(s19, 0.0f);

  __ Fmov(d26, -0.0);
  __ Fmov(d27, kFP64PositiveInfinity);
  __ Fmov(d28, kFP64NegativeInfinity);
  __ Fmov(d29, 0.0);
  __ Fmov(d30, -2.0);
  __ Fmov(d31, 2.25);

  __ Fadd(s0, s17, s18);
  __ Fadd(s1, s18, s19);
  __ Fadd(s2, s14, s18);
  __ Fadd(s3, s15, s18);
  __ Fadd(s4, s16, s18);
  __ Fadd(s5, s15, s16);
  __ Fadd(s6, s16, s15);

  __ Fadd(d7, d30, d31);
  __ Fadd(d8, d29, d31);
  __ Fadd(d9, d26, d31);
  __ Fadd(d10, d27, d31);
  __ Fadd(d11, d28, d31);
  __ Fadd(d12, d27, d28);
  __ Fadd(d13, d28, d27);
  END();

  RUN();

  CHECK_EQUAL_FP32(4.25, s0);
  CHECK_EQUAL_FP32(1.0, s1);
  CHECK_EQUAL_FP32(1.0, s2);
  CHECK_EQUAL_FP32(kFP32PositiveInfinity, s3);
  CHECK_EQUAL_FP32(kFP32NegativeInfinity, s4);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s5);
  CHECK_EQUAL_FP32(kFP32DefaultNaN, s6);
  CHECK_EQUAL_FP64(0.25, d7);
  CHECK_EQUAL_FP64(2.25, d8);
  CHECK_EQUAL_FP64(2.25, d9);
  CHECK_EQUAL_FP64(kFP64PositiveInfinity, d10);
  CHECK_EQUAL_FP64(kFP64NegativeInfinity, d11);
  CHECK_EQUAL_FP64(k
```