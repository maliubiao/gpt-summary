Response:
The user wants me to analyze a C++ file containing V8 tests for ARM64 assembler instructions. I need to extract the functionalities tested, and if any relate to Javascript, illustrate with a Javascript example. If there's logic, I should provide input and output examples. I also need to identify potential programming errors and provide examples, and finally, summarize the functionality of this specific code snippet, keeping in mind it's part 2 of 15.

Here's a breakdown of the code snippet's functionality:

1. **Initialization and Setup:** Each `TEST` function starts with `INIT_V8()` and `SETUP()`, indicating the initialization of the V8 testing environment and setting up the necessary conditions for the test.
2. **Register Manipulation:**  The tests heavily utilize ARM64 registers (x0-x30, w0-w30, lr) to load values and perform operations.
3. **Arithmetic Instructions:** The code tests various arithmetic instructions:
    - `Add`: Addition (with carry and immediate variants).
    - `Sub`: Subtraction (with borrow and immediate variants).
    - `Mul`: Multiplication (including widening and negation).
    - `Smull`: Signed multiply low.
    - `Madd`: Multiply-add.
    - `Msub`: Multiply-subtract.
    - `Smulh`: Signed multiply high.
    - `Smaddl`, `Umaddl`: Signed and unsigned multiply-add long.
    - `Smsubl`, `Umsubl`: Signed and unsigned multiply-subtract long.
    - `Udiv`, `Sdiv`: Unsigned and signed division.
4. **Bit Manipulation Instructions:**
    - `Rbit`: Reverse bits.
    - `Rev16`, `Rev`, `Rev32`: Reverse bytes within words and doublewords.
    - `Clz`: Count leading zeros.
    - `Cls`: Count leading sign bits.
5. **Control Flow Instructions:**
    - `B`: Branch (unconditional).
    - `Bl`: Branch with link (for function calls).
    - `Br`: Branch to register.
    - `Blr`: Branch with link to register.
    - `Ret`: Return from subroutine.
    - `Cmp`: Compare.
    - Conditional branches (e.g., `Beq`, `Bne`, `Blt`, etc.).
    - `Cbz`, `Cbnz`: Compare and branch if zero/non-zero.
    - `Tbz`, `Tbnz`: Test bit and branch if zero/non-zero.
    - `Adr`: Address of label.
6. **Labels:** The code uses labels to define jump targets and manage control flow. It tests forward and backward branches, and branches to the start of the buffer.
7. **Branch Target Identification (BTI):**  Tests related to BTI, a security feature, are present.
8. **Veneers:** The code explicitly tests the generation of veneers for long-range branches.
9. **Testing Framework:** The code uses a testing framework with `TEST()`, `INIT_V8()`, `SETUP()`, `START()`, `END()`, `RUN()`, and `CHECK_EQUAL_64()`.

Relating this to Javascript is challenging because these are low-level assembler tests. However, some operations have higher-level equivalents. For instance, multiplication and division in Javascript use the `*` and `/` operators, which eventually translate to lower-level instructions like `Mul` and `Div`. Bitwise operations in Javascript (`&`, `|`, `^`, `~`, `<<`, `>>`, `>>>`) have corresponding assembly instructions, although they are not directly tested in this snippet.

Regarding potential programming errors, using incorrect register sizes (e.g., using a 32-bit register when a 64-bit one is required) or incorrect conditional branch codes can lead to unexpected behavior. Division by zero is also a classic error, which the `div` test seems to touch upon by dividing by 0 and checking the result.

Considering this is part 2 of 15, it's likely focused on testing a specific set of ARM64 instructions related to arithmetic, bit manipulation, and basic control flow. The inclusion of BTI and veneer tests indicates a focus on code generation correctness and security.
```cpp
  CHECK_EQUAL_64(0x0, x0);
}
```

这是 `v8/test/cctest/test-assembler-arm64.cc` 的第 2 部分，它主要专注于测试 ARM64 汇编器中各种**算术、逻辑和控制流指令**的正确性。

**功能列举:**

1. **算术运算指令测试:**
   - `add`: 测试加法指令，包括带进位的加法和立即数加法。
   - `sub`: 测试减法指令，包括带借位的减法和立即数减法。
   - `mul`: 测试乘法指令，包括 32 位和 64 位乘法，以及有符号扩展乘法 (`smull`) 和乘法取反指令 (`mneg`)。
   - `smull`: 提供辅助函数 `SmullHelper` 来测试有符号乘法低位结果。
   - `madd`: 测试乘加指令。
   - `msub`: 测试乘减指令。
   - `smulh`: 测试有符号乘法高位结果。
   - `smaddl_umaddl`: 测试有符号和无符号的乘加长指令。
   - `smsubl_umsubl`: 测试有符号和无符号的乘减长指令。
   - `div`: 测试无符号除法 (`udiv`) 和有符号除法 (`sdiv`) 指令。

2. **位操作指令测试:**
   - `rbit_rev`: 测试位反转指令 (`rbit`) 和字节序反转指令 (`rev16`, `rev`, `rev32`)。
   - `clz_cls`: 测试计算前导零指令 (`clz`) 和计算前导符号位指令 (`cls`)。

3. **控制流指令测试:**
   - `label`: 测试标签的定义和跳转功能，包括向前和向后跳转，以及多个分支跳转到同一标签。
   - `branch_at_start`: 测试在代码缓冲区的起始位置进行分支跳转。
   - `adr`: 测试 `adr` 指令，用于加载与程序计数器相对的地址。
   - `adr_far`: 测试 `adr` 指令在目标地址超出指令直接寻址范围时的行为，并涉及到生成远跳转代码（veneer）。
   - `branch_cond`: 测试各种条件分支指令，并验证在不同条件下是否正确跳转。
   - `branch_to_reg`: 测试跳转到寄存器指令 (`br`) 和带链接跳转到寄存器指令 (`blr`)，用于函数调用。
   - `bti`: 测试分支目标标识 (Branch Target Identification, BTI) 相关指令，这是一种安全特性。
   - `unguarded_bti_is_nop`: 测试在 BTI 保护关闭时，BTI 指令是否会变成 `nop` 指令。
   - `compare_branch`: 测试比较并分支指令 (`cbz`, `cbnz`)。
   - `test_branch`: 测试位测试并分支指令 (`tbz`, `tbnz`)。
   - `far_branch_backward`: 测试向后远跳转，并验证是否正确生成跳转代码。
   - `far_branch_simple_veneer`: 测试向前远跳转，并验证是否正确生成跳转代码 (veneer)。
   - `far_branch_veneer_link_chain`: 测试多个分支链接到同一个超出范围的目标地址时，是否正确生成跳转代码。
   - `far_branch_veneer_broken_link_chain`: 测试在跳转链接链中断裂的情况下，汇编器是否能正确处理。
   - `branch_type`:  测试各种类型的分支指令，包括无条件分支、条件分支、寄存器零/非零分支以及位测试分支。

**v8 torque源代码关系:**

如果 `v8/test/cctest/test-assembler-arm64.cc` 以 `.tq` 结尾，那它就是一个 V8 Torque 源代码。然而，根据文件名判断，当前文件是 `.cc` 结尾，因此是 C++ 源代码，用于测试 ARM64 汇编器。 Torque 通常用于生成高效的运行时代码，但这个文件是用于测试汇编器本身的。

**与 javascript 的功能关系:**

虽然这是汇编器的测试代码，但它测试的指令是 JavaScript 引擎在底层执行 JavaScript 代码时会用到的。例如：

```javascript
let a = 5;
let b = 10;
let sum = a + b; //  '+' 操作在底层可能使用 add 指令

let c = a * b;   //  '*' 操作在底层可能使用 mul 指令

if (a > b) {      //  '>' 比较在底层可能使用 cmp 和条件分支指令
  // ...
}
```

在 JavaScript 中执行算术运算、位操作和控制流语句时，V8 引擎会将这些高级操作转换为底层的 ARM64 汇编指令。这个测试文件就是用来确保 V8 生成的这些指令是正确的。

**代码逻辑推理 (假设输入与输出):**

**例1: `TEST(add)`**

假设执行 `TEST(add)` 中的以下代码段:

```cpp
  __ Mov(x6, 0xEEEEEE66);
  __ Add(x6, x6, Operand(3));
  __ Mov(x7, 0xEEEEEEEEEEEFEFE8UL);
  __ Add(x7, x7, Operand(0x3));
```

* **假设输入:**
    - 寄存器 `x6` 的初始值为 `0xEEEEEE66`
    - 寄存器 `x7` 的初始值为 `0xEEEEEEEEEEEFEFE8`

* **代码逻辑:**
    - `__ Add(x6, x6, Operand(3));` 将 `x6` 的值加上 3。
    - `__ Add(x7, x7, Operand(0x3));` 将 `x7` 的值加上 3。

* **预期输出:**
    - 寄存器 `x6` 的最终值为 `0xEEEEEE69`
    - 寄存器 `x7` 的最终值为 `0xEEEEEEEEEEEFEFEB`

**例2: `TEST(mul)`**

假设执行 `TEST(mul)` 中的以下代码段:

```cpp
  __ Mov(w0, w16, w16); // w16 初始化为 0
  __ Mul(w0, w16, w16);
```

* **假设输入:**
    - 寄存器 `w16` 的初始值为 `0`

* **代码逻辑:**
    - `__ Mul(w0, w16, w16);` 计算 `w16 * w16` 的结果并存储到 `w0`。

* **预期输出:**
    - 寄存器 `w0` 的最终值为 `0`

**用户常见的编程错误举例:**

1. **整数溢出:**  在进行算术运算时，结果超出了寄存器能表示的范围。例如，在 `TEST(add)` 中，如果没有考虑到进位，可能会忽略溢出。

   ```cpp
   // 假设 w0 的最大值是 0xFFFFFFFF
   __ Mov(w0, 0xFFFFFFFF);
   __ Add(w0, w0, Operand(1));
   // 用户可能期望 w0 为 0x100000000，但实际 w0 会变为 0 (忽略溢出)
   ```

2. **类型不匹配:**  在进行位操作或算术运算时，使用了不匹配大小的寄存器。

   ```cpp
   __ Mov(x0, 0xFFFFFFFF00000000UL); // 64 位值
   __ Clz(w1, w0); // 尝试对 64 位值使用 32 位 clz 指令 (虽然 clz 可以处理 64 位，但这里展示了类型不匹配的概念)
   ```

3. **条件分支使用错误:**  使用了错误的条件代码，导致程序在不应该跳转的时候跳转，或者在应该跳转的时候没有跳转。

   ```cpp
   __ Cmp(x1, x2);
   __ B(&some_label, eq); // 如果 x1 不等于 x2，则不会跳转，但程序员可能错误地以为会跳转
   ```

4. **除零错误:**  进行除法运算时，除数为零。这在 `TEST(div)` 中有所涉及，该测试会检查除零的结果。

   ```cpp
   __ Mov(w1, 0);
   __ Udiv(w0, w2, w1); // 除数为零，结果未定义
   ```

**功能归纳 (第 2 部分):**

`v8/test/cctest/test-assembler-arm64.cc` 的第 2 部分主要通过单元测试，**验证了 ARM64 汇编器生成代码的正确性**，涵盖了基本的算术运算、位操作以及各种控制流指令的实现。它确保了 V8 引擎在 ARM64 架构上生成正确的机器码，从而保证 JavaScript 代码的性能和正确性。 这部分测试涵盖了指令的基本功能和一些边界情况，例如远跳转和 BTI 等安全特性。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共15部分，请归纳一下它的功能

"""
));
  END();

  RUN();

  CHECK_EQUAL_64(0xEEEEEE6F, x6);
  CHECK_EQUAL_64(0xEEEEEEEEEEEFEFECUL, x7);
  CHECK_EQUAL_64(0xEEECECEA, x8);
  CHECK_EQUAL_64(0xEEEEEEEAEEEAEAE6UL, x9);
  CHECK_EQUAL_64(0x1111116F, x10);
  CHECK_EQUAL_64(0x111111111111EFECUL, x11);
  CHECK_EQUAL_64(0x11111110EEECECEAUL, x12);
  CHECK_EQUAL_64(0xEEEEEEEAEEEAEAE6UL, x13);
}

TEST(mul) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x15, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Mul(w0, w16, w16);
  __ Mul(w1, w16, w17);
  __ Mul(w2, w17, w15);
  __ Mul(w3, w15, w19);
  __ Mul(x4, x16, x16);
  __ Mul(x5, x17, x15);
  __ Mul(x6, x15, x19);
  __ Mul(x7, x19, x19);
  __ Smull(x8, w17, w15);
  __ Smull(x9, w15, w15);
  __ Smull(x10, w19, w19);
  __ Mneg(w11, w16, w16);
  __ Mneg(w12, w16, w17);
  __ Mneg(w13, w17, w15);
  __ Mneg(w14, w15, w19);
  __ Mneg(x20, x16, x16);
  __ Mneg(x21, x17, x15);
  __ Mneg(x22, x15, x19);
  __ Mneg(x23, x19, x19);
  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(1, x3);
  CHECK_EQUAL_64(0, x4);
  CHECK_EQUAL_64(0xFFFFFFFF, x5);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x8);
  CHECK_EQUAL_64(1, x9);
  CHECK_EQUAL_64(1, x10);
  CHECK_EQUAL_64(0, x11);
  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0, x20);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x21);
  CHECK_EQUAL_64(0xFFFFFFFF, x22);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x23);
}

static void SmullHelper(int64_t expected, int64_t a, int64_t b) {
  SETUP();
  START();
  __ Mov(w0, a);
  __ Mov(w1, b);
  __ Smull(x2, w0, w1);
  END();
  RUN();
  CHECK_EQUAL_64(expected, x2);
}

TEST(smull) {
  INIT_V8();
  SmullHelper(0, 0, 0);
  SmullHelper(1, 1, 1);
  SmullHelper(-1, -1, 1);
  SmullHelper(1, -1, -1);
  SmullHelper(0xFFFFFFFF80000000, 0x80000000, 1);
  SmullHelper(0x0000000080000000, 0x00010000, 0x00008000);
}

TEST(madd) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Madd(w0, w16, w16, w16);
  __ Madd(w1, w16, w16, w17);
  __ Madd(w2, w16, w16, w28);
  __ Madd(w3, w16, w16, w19);
  __ Madd(w4, w16, w17, w17);
  __ Madd(w5, w17, w17, w28);
  __ Madd(w6, w17, w17, w19);
  __ Madd(w7, w17, w28, w16);
  __ Madd(w8, w17, w28, w28);
  __ Madd(w9, w28, w28, w17);
  __ Madd(w10, w28, w19, w28);
  __ Madd(w11, w19, w19, w19);

  __ Madd(x12, x16, x16, x16);
  __ Madd(x13, x16, x16, x17);
  __ Madd(x14, x16, x16, x28);
  __ Madd(x15, x16, x16, x19);
  __ Madd(x20, x16, x17, x17);
  __ Madd(x21, x17, x17, x28);
  __ Madd(x22, x17, x17, x19);
  __ Madd(x23, x17, x28, x16);
  __ Madd(x24, x17, x28, x28);
  __ Madd(x25, x28, x28, x17);
  __ Madd(x26, x28, x19, x28);
  __ Madd(x27, x19, x19, x19);

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0, x5);
  CHECK_EQUAL_64(0, x6);
  CHECK_EQUAL_64(0xFFFFFFFF, x7);
  CHECK_EQUAL_64(0xFFFFFFFE, x8);
  CHECK_EQUAL_64(2, x9);
  CHECK_EQUAL_64(0, x10);
  CHECK_EQUAL_64(0, x11);

  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFF, x15);
  CHECK_EQUAL_64(1, x20);
  CHECK_EQUAL_64(0x100000000UL, x21);
  CHECK_EQUAL_64(0, x22);
  CHECK_EQUAL_64(0xFFFFFFFF, x23);
  CHECK_EQUAL_64(0x1FFFFFFFE, x24);
  CHECK_EQUAL_64(0xFFFFFFFE00000002UL, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0, x27);
}

TEST(msub) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 0);
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);

  __ Msub(w0, w16, w16, w16);
  __ Msub(w1, w16, w16, w17);
  __ Msub(w2, w16, w16, w28);
  __ Msub(w3, w16, w16, w19);
  __ Msub(w4, w16, w17, w17);
  __ Msub(w5, w17, w17, w28);
  __ Msub(w6, w17, w17, w19);
  __ Msub(w7, w17, w28, w16);
  __ Msub(w8, w17, w28, w28);
  __ Msub(w9, w28, w28, w17);
  __ Msub(w10, w28, w19, w28);
  __ Msub(w11, w19, w19, w19);

  __ Msub(x12, x16, x16, x16);
  __ Msub(x13, x16, x16, x17);
  __ Msub(x14, x16, x16, x28);
  __ Msub(x15, x16, x16, x19);
  __ Msub(x20, x16, x17, x17);
  __ Msub(x21, x17, x17, x28);
  __ Msub(x22, x17, x17, x19);
  __ Msub(x23, x17, x28, x16);
  __ Msub(x24, x17, x28, x28);
  __ Msub(x25, x28, x28, x17);
  __ Msub(x26, x28, x19, x28);
  __ Msub(x27, x19, x19, x19);

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(1, x1);
  CHECK_EQUAL_64(0xFFFFFFFF, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0xFFFFFFFE, x5);
  CHECK_EQUAL_64(0xFFFFFFFE, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0, x9);
  CHECK_EQUAL_64(0xFFFFFFFE, x10);
  CHECK_EQUAL_64(0xFFFFFFFE, x11);

  CHECK_EQUAL_64(0, x12);
  CHECK_EQUAL_64(1, x13);
  CHECK_EQUAL_64(0xFFFFFFFF, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x15);
  CHECK_EQUAL_64(1, x20);
  CHECK_EQUAL_64(0xFFFFFFFEUL, x21);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x22);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x23);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x200000000UL, x25);
  CHECK_EQUAL_64(0x1FFFFFFFEUL, x26);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFEUL, x27);
}

TEST(smulh) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x20, 0);
  __ Mov(x21, 1);
  __ Mov(x22, 0x0000000100000000L);
  __ Mov(x23, 0x12345678);
  __ Mov(x24, 0x0123456789ABCDEFL);
  __ Mov(x25, 0x0000000200000000L);
  __ Mov(x26, 0x8000000000000000UL);
  __ Mov(x27, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x28, 0x5555555555555555UL);
  __ Mov(x29, 0xAAAAAAAAAAAAAAAAUL);

  __ Smulh(x0, x20, x24);
  __ Smulh(x1, x21, x24);
  __ Smulh(x2, x22, x23);
  __ Smulh(x3, x22, x24);
  __ Smulh(x4, x24, x25);
  __ Smulh(x5, x23, x27);
  __ Smulh(x6, x26, x26);
  __ Smulh(x7, x26, x27);
  __ Smulh(x8, x27, x27);
  __ Smulh(x9, x28, x28);
  __ Smulh(x10, x28, x29);
  __ Smulh(x11, x29, x29);
  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0, x2);
  CHECK_EQUAL_64(0x01234567, x3);
  CHECK_EQUAL_64(0x02468ACF, x4);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFUL, x5);
  CHECK_EQUAL_64(0x4000000000000000UL, x6);
  CHECK_EQUAL_64(0, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0x1C71C71C71C71C71UL, x9);
  CHECK_EQUAL_64(0xE38E38E38E38E38EUL, x10);
  CHECK_EQUAL_64(0x1C71C71C71C71C72UL, x11);
}

TEST(smaddl_umaddl) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x20, 4);
  __ Mov(x21, 0x200000000UL);

  __ Smaddl(x9, w17, w28, x20);
  __ Smaddl(x10, w28, w28, x20);
  __ Smaddl(x11, w19, w19, x20);
  __ Smaddl(x12, w19, w19, x21);
  __ Umaddl(x13, w17, w28, x20);
  __ Umaddl(x14, w28, w28, x20);
  __ Umaddl(x15, w19, w19, x20);
  __ Umaddl(x22, w19, w19, x21);
  END();

  RUN();

  CHECK_EQUAL_64(3, x9);
  CHECK_EQUAL_64(5, x10);
  CHECK_EQUAL_64(5, x11);
  CHECK_EQUAL_64(0x200000001UL, x12);
  CHECK_EQUAL_64(0x100000003UL, x13);
  CHECK_EQUAL_64(0xFFFFFFFE00000005UL, x14);
  CHECK_EQUAL_64(0xFFFFFFFE00000005UL, x15);
  CHECK_EQUAL_64(0x1, x22);
}

TEST(smsubl_umsubl) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x17, 1);
  __ Mov(x28, 0xFFFFFFFF);
  __ Mov(x19, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x20, 4);
  __ Mov(x21, 0x200000000UL);

  __ Smsubl(x9, w17, w28, x20);
  __ Smsubl(x10, w28, w28, x20);
  __ Smsubl(x11, w19, w19, x20);
  __ Smsubl(x12, w19, w19, x21);
  __ Umsubl(x13, w17, w28, x20);
  __ Umsubl(x14, w28, w28, x20);
  __ Umsubl(x15, w19, w19, x20);
  __ Umsubl(x22, w19, w19, x21);
  END();

  RUN();

  CHECK_EQUAL_64(5, x9);
  CHECK_EQUAL_64(3, x10);
  CHECK_EQUAL_64(3, x11);
  CHECK_EQUAL_64(0x1FFFFFFFFUL, x12);
  CHECK_EQUAL_64(0xFFFFFFFF00000005UL, x13);
  CHECK_EQUAL_64(0x200000003UL, x14);
  CHECK_EQUAL_64(0x200000003UL, x15);
  CHECK_EQUAL_64(0x3FFFFFFFFUL, x22);
}

TEST(div) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x16, 1);
  __ Mov(x17, 0xFFFFFFFF);
  __ Mov(x30, 0xFFFFFFFFFFFFFFFFUL);
  __ Mov(x19, 0x80000000);
  __ Mov(x20, 0x8000000000000000UL);
  __ Mov(x21, 2);

  __ Udiv(w0, w16, w16);
  __ Udiv(w1, w17, w16);
  __ Sdiv(w2, w16, w16);
  __ Sdiv(w3, w16, w17);
  __ Sdiv(w4, w17, w30);

  __ Udiv(x5, x16, x16);
  __ Udiv(x6, x17, x30);
  __ Sdiv(x7, x16, x16);
  __ Sdiv(x8, x16, x17);
  __ Sdiv(x9, x17, x30);

  __ Udiv(w10, w19, w21);
  __ Sdiv(w11, w19, w21);
  __ Udiv(x12, x19, x21);
  __ Sdiv(x13, x19, x21);
  __ Udiv(x14, x20, x21);
  __ Sdiv(x15, x20, x21);

  __ Udiv(w22, w19, w17);
  __ Sdiv(w23, w19, w17);
  __ Udiv(x24, x20, x30);
  __ Sdiv(x25, x20, x30);

  __ Udiv(x26, x16, x21);
  __ Sdiv(x27, x16, x21);
  __ Udiv(x28, x30, x21);
  __ Sdiv(x29, x30, x21);

  __ Mov(x17, 0);
  __ Udiv(w30, w16, w17);
  __ Sdiv(w19, w16, w17);
  __ Udiv(x20, x16, x17);
  __ Sdiv(x21, x16, x17);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0xFFFFFFFF, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0xFFFFFFFF, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(1, x5);
  CHECK_EQUAL_64(0, x6);
  CHECK_EQUAL_64(1, x7);
  CHECK_EQUAL_64(0, x8);
  CHECK_EQUAL_64(0xFFFFFFFF00000001UL, x9);
  CHECK_EQUAL_64(0x40000000, x10);
  CHECK_EQUAL_64(0xC0000000, x11);
  CHECK_EQUAL_64(0x40000000, x12);
  CHECK_EQUAL_64(0x40000000, x13);
  CHECK_EQUAL_64(0x4000000000000000UL, x14);
  CHECK_EQUAL_64(0xC000000000000000UL, x15);
  CHECK_EQUAL_64(0, x22);
  CHECK_EQUAL_64(0x80000000, x23);
  CHECK_EQUAL_64(0, x24);
  CHECK_EQUAL_64(0x8000000000000000UL, x25);
  CHECK_EQUAL_64(0, x26);
  CHECK_EQUAL_64(0, x27);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFUL, x28);
  CHECK_EQUAL_64(0, x29);
  CHECK_EQUAL_64(0, x30);
  CHECK_EQUAL_64(0, x19);
  CHECK_EQUAL_64(0, x20);
  CHECK_EQUAL_64(0, x21);
}

TEST(rbit_rev) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x24, 0xFEDCBA9876543210UL);
  __ Rbit(w0, w24);
  __ Rbit(x1, x24);
  __ Rev16(w2, w24);
  __ Rev16(x3, x24);
  __ Rev(w4, w24);
  __ Rev32(x5, x24);
  __ Rev(x6, x24);
  END();

  RUN();

  CHECK_EQUAL_64(0x084C2A6E, x0);
  CHECK_EQUAL_64(0x084C2A6E195D3B7FUL, x1);
  CHECK_EQUAL_64(0x54761032, x2);
  CHECK_EQUAL_64(0xDCFE98BA54761032UL, x3);
  CHECK_EQUAL_64(0x10325476, x4);
  CHECK_EQUAL_64(0x98BADCFE10325476UL, x5);
  CHECK_EQUAL_64(0x1032547698BADCFEUL, x6);
}

TEST(clz_cls) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x24, 0x0008000000800000UL);
  __ Mov(x25, 0xFF800000FFF80000UL);
  __ Mov(x26, 0);
  __ Clz(w0, w24);
  __ Clz(x1, x24);
  __ Clz(w2, w25);
  __ Clz(x3, x25);
  __ Clz(w4, w26);
  __ Clz(x5, x26);
  __ Cls(w6, w24);
  __ Cls(x7, x24);
  __ Cls(w8, w25);
  __ Cls(x9, x25);
  __ Cls(w10, w26);
  __ Cls(x11, x26);
  END();

  RUN();

  CHECK_EQUAL_64(8, x0);
  CHECK_EQUAL_64(12, x1);
  CHECK_EQUAL_64(0, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(32, x4);
  CHECK_EQUAL_64(64, x5);
  CHECK_EQUAL_64(7, x6);
  CHECK_EQUAL_64(11, x7);
  CHECK_EQUAL_64(12, x8);
  CHECK_EQUAL_64(8, x9);
  CHECK_EQUAL_64(31, x10);
  CHECK_EQUAL_64(63, x11);
}

TEST(label) {
  INIT_V8();
  SETUP();

  Label label_1, label_2, label_3, label_4;

  START();
  __ Mov(x0, 0x1);
  __ Mov(x1, 0x0);
  __ Mov(x22, lr);    // Save lr.

  __ B(&label_1);
  __ B(&label_1);
  __ B(&label_1);     // Multiple branches to the same label.
  __ Mov(x0, 0x0);
  __ Bind(&label_2);
  __ B(&label_3);     // Forward branch.
  __ Mov(x0, 0x0);
  __ Bind(&label_1);
  __ B(&label_2);     // Backward branch.
  __ Mov(x0, 0x0);
  __ Bind(&label_3);
  __ Bl(&label_4);
  END();

  __ Bind(&label_4);
  __ Mov(x1, 0x1);
  __ Mov(lr, x22);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(branch_at_start) {
  INIT_V8();
  SETUP();

  Label good, exit;

  // Test that branches can exist at the start of the buffer. (This is a
  // boundary condition in the label-handling code.) To achieve this, we have
  // to work around the code generated by START.
  RESET();
  __ B(&good);

  START_AFTER_RESET();
  __ Mov(x0, 0x0);
  END();

  __ Bind(&exit);
  START_AFTER_RESET();
  __ Mov(x0, 0x1);
  END();

  __ Bind(&good);
  __ B(&exit);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
}

TEST(adr) {
  INIT_V8();
  SETUP();

  Label label_1, label_2, label_3, label_4;

  START();
  __ Mov(x0, 0x0);        // Set to non-zero to indicate failure.
  __ Adr(x1, &label_3);   // Set to zero to indicate success.

  __ Adr(x2, &label_1);   // Multiple forward references to the same label.
  __ Adr(x3, &label_1);
  __ Adr(x4, &label_1);

  __ Bind(&label_2, BranchTargetIdentifier::kBtiJump);
  __ Eor(x5, x2, Operand(x3));  // Ensure that x2,x3 and x4 are identical.
  __ Eor(x6, x2, Operand(x4));
  __ Orr(x0, x0, Operand(x5));
  __ Orr(x0, x0, Operand(x6));
  __ Br(x2);  // label_1, label_3

  __ Bind(&label_3, BranchTargetIdentifier::kBtiJump);
  __ Adr(x2, &label_3);   // Self-reference (offset 0).
  __ Eor(x1, x1, Operand(x2));
  __ Adr(x2, &label_4);   // Simple forward reference.
  __ Br(x2);  // label_4

  __ Bind(&label_1, BranchTargetIdentifier::kBtiJump);
  __ Adr(x2, &label_3);   // Multiple reverse references to the same label.
  __ Adr(x3, &label_3);
  __ Adr(x4, &label_3);
  __ Adr(x5, &label_2);   // Simple reverse reference.
  __ Br(x5);  // label_2

  __ Bind(&label_4, BranchTargetIdentifier::kBtiJump);
  END();

  RUN();

  CHECK_EQUAL_64(0x0, x0);
  CHECK_EQUAL_64(0x0, x1);
}

TEST(adr_far) {
  INIT_V8();

  int max_range = 1 << (Instruction::ImmPCRelRangeBitwidth - 1);
  SETUP_SIZE(max_range + 1000 * kInstrSize);

  Label done, fail;
  Label test_near, near_forward, near_backward;
  Label test_far, far_forward, far_backward;

  START();
  __ Mov(x0, 0x0);

  __ Bind(&test_near);
  __ Adr(x10, &near_forward, MacroAssembler::kAdrFar);
  __ Br(x10);
  __ B(&fail);
  __ Bind(&near_backward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_far);

  __ Bind(&near_forward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 0);
  __ Adr(x10, &near_backward, MacroAssembler::kAdrFar);
  __ Br(x10);

  __ Bind(&test_far);
  __ Adr(x10, &far_forward, MacroAssembler::kAdrFar);
  __ Br(x10);
  __ B(&fail);
  __ Bind(&far_backward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 3);
  __ B(&done);

  for (int i = 0; i < max_range / kInstrSize + 1; ++i) {
    if (i % 100 == 0) {
      // If we do land in this code, we do not want to execute so many nops
      // before reaching the end of test (especially if tracing is activated).
      __ b(&fail);
    } else {
      __ nop();
    }
  }

  __ Bind(&far_forward, BranchTargetIdentifier::kBtiJump);
  __ Orr(x0, x0, 1 << 2);
  __ Adr(x10, &far_backward, MacroAssembler::kAdrFar);
  __ Br(x10);

  __ B(&done);
  __ Bind(&fail);
  __ Orr(x0, x0, 1 << 4);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0xF, x0);
}

TEST(branch_cond) {
  INIT_V8();
  SETUP();

  Label wrong;

  START();
  __ Mov(x0, 0x1);
  __ Mov(x1, 0x1);
  __ Mov(x2, 0x8000000000000000L);

  // For each 'cmp' instruction below, condition codes other than the ones
  // following it would branch.

  __ Cmp(x1, 0);
  __ B(&wrong, eq);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vs);
  __ B(&wrong, ls);
  __ B(&wrong, lt);
  __ B(&wrong, le);
  Label ok_1;
  __ B(&ok_1, ne);
  __ Mov(x0, 0x0);
  __ Bind(&ok_1);

  __ Cmp(x1, 1);
  __ B(&wrong, ne);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vs);
  __ B(&wrong, hi);
  __ B(&wrong, lt);
  __ B(&wrong, gt);
  Label ok_2;
  __ B(&ok_2, pl);
  __ Mov(x0, 0x0);
  __ Bind(&ok_2);

  __ Cmp(x1, 2);
  __ B(&wrong, eq);
  __ B(&wrong, hs);
  __ B(&wrong, pl);
  __ B(&wrong, vs);
  __ B(&wrong, hi);
  __ B(&wrong, ge);
  __ B(&wrong, gt);
  Label ok_3;
  __ B(&ok_3, vc);
  __ Mov(x0, 0x0);
  __ Bind(&ok_3);

  __ Cmp(x2, 1);
  __ B(&wrong, eq);
  __ B(&wrong, lo);
  __ B(&wrong, mi);
  __ B(&wrong, vc);
  __ B(&wrong, ls);
  __ B(&wrong, ge);
  __ B(&wrong, gt);
  Label ok_4;
  __ B(&ok_4, le);
  __ Mov(x0, 0x0);
  __ Bind(&ok_4);

  Label ok_5;
  __ b(&ok_5, al);
  __ Mov(x0, 0x0);
  __ Bind(&ok_5);

  Label ok_6;
  __ b(&ok_6, nv);
  __ Mov(x0, 0x0);
  __ Bind(&ok_6);

  END();

  __ Bind(&wrong);
  __ Mov(x0, 0x0);
  END();

  RUN();

  CHECK_EQUAL_64(0x1, x0);
}

TEST(branch_to_reg) {
  INIT_V8();
  SETUP();

  // Test br.
  Label fn1, after_fn1, after_bl1;

  START();
  __ Mov(x29, lr);

  __ Mov(x1, 0);
  __ B(&after_fn1);

  __ Bind(&fn1);
  __ Mov(x0, lr);
  __ Mov(x1, 42);
  __ Br(x0);

  __ Bind(&after_fn1);
  __ Bl(&fn1);
  __ Bind(&after_bl1, BranchTargetIdentifier::kBtiJump);  // For Br(x0) in fn1.

  // Test blr.
  Label fn2, after_fn2, after_bl2;

  __ Mov(x2, 0);
  __ B(&after_fn2);

  __ Bind(&fn2);
  __ Mov(x0, lr);
  __ Mov(x2, 84);
  __ Blr(x0);

  __ Bind(&after_fn2);
  __ Bl(&fn2);
  __ Bind(&after_bl2, BranchTargetIdentifier::kBtiCall);  // For Blr(x0) in fn2.
  __ Mov(x3, lr);

  __ Mov(lr, x29);
  END();

  RUN();

  CHECK_EQUAL_64(core.xreg(3) + kInstrSize, x0);
  CHECK_EQUAL_64(42, x1);
  CHECK_EQUAL_64(84, x2);
}

static void BtiHelper(Register ipreg) {
  SETUP();

  Label jump_target, jump_call_target, call_target, test_pacibsp,
      pacibsp_target, done;
  START();
  UseScratchRegisterScope temps(&masm);
  temps.Exclude(ipreg);

  __ Adr(x0, &jump_target);
  __ Br(x0);
  __ Nop();

  __ Bind(&jump_target, BranchTargetIdentifier::kBtiJump);
  __ Adr(x0, &call_target);
  __ Blr(x0);

  __ Adr(ipreg, &jump_call_target);
  __ Blr(ipreg);
  __ Adr(lr, &test_pacibsp);  // Make Ret return to test_pacibsp.
  __ Br(ipreg);

  __ Bind(&test_pacibsp, BranchTargetIdentifier::kNone);
  __ Adr(ipreg, &pacibsp_target);
  __ Blr(ipreg);
  __ Adr(lr, &done);  // Make Ret return to done label.
  __ Br(ipreg);

  __ Bind(&call_target, BranchTargetIdentifier::kBtiCall);
  __ Ret();

  __ Bind(&jump_call_target, BranchTargetIdentifier::kBtiJumpCall);
  __ Ret();

  __ Bind(&pacibsp_target, BranchTargetIdentifier::kPacibsp);
  __ Autibsp();
  __ Ret();

  __ Bind(&done);
  END();

#ifdef USE_SIMULATOR
  simulator.SetGuardedPages(true);
  RUN();
#endif  // USE_SIMULATOR
}

TEST(bti) {
  BtiHelper(x16);
  BtiHelper(x17);
}

TEST(unguarded_bti_is_nop) {
  SETUP();

  Label start, none, c, j, jc;
  START();
  __ B(&start);
  __ Bind(&none, BranchTargetIdentifier::kBti);
  __ Bind(&c, BranchTargetIdentifier::kBtiCall);
  __ Bind(&j, BranchTargetIdentifier::kBtiJump);
  __ Bind(&jc, BranchTargetIdentifier::kBtiJumpCall);
  CHECK(__ SizeOfCodeGeneratedSince(&none) == 4 * kInstrSize);
  __ Ret();

  Label jump_to_c, call_to_j;
  __ Bind(&start);
  __ Adr(x0, &none);
  __ Adr(lr, &jump_to_c);
  __ Br(x0);

  __ Bind(&jump_to_c);
  __ Adr(x0, &c);
  __ Adr(lr, &call_to_j);
  __ Br(x0);

  __ Bind(&call_to_j);
  __ Adr(x0, &j);
  __ Blr(x0);
  END();

#ifdef USE_SIMULATOR
  simulator.SetGuardedPages(false);
  RUN();
#endif  // USE_SIMULATOR
}

TEST(compare_branch) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);
  __ Mov(x3, 0);
  __ Mov(x4, 0);
  __ Mov(x5, 0);
  __ Mov(x16, 0);
  __ Mov(x17, 42);

  Label zt, zt_end;
  __ Cbz(w16, &zt);
  __ B(&zt_end);
  __ Bind(&zt);
  __ Mov(x0, 1);
  __ Bind(&zt_end);

  Label zf, zf_end;
  __ Cbz(x17, &zf);
  __ B(&zf_end);
  __ Bind(&zf);
  __ Mov(x1, 1);
  __ Bind(&zf_end);

  Label nzt, nzt_end;
  __ Cbnz(w17, &nzt);
  __ B(&nzt_end);
  __ Bind(&nzt);
  __ Mov(x2, 1);
  __ Bind(&nzt_end);

  Label nzf, nzf_end;
  __ Cbnz(x16, &nzf);
  __ B(&nzf_end);
  __ Bind(&nzf);
  __ Mov(x3, 1);
  __ Bind(&nzf_end);

  __ Mov(x19, 0xFFFFFFFF00000000UL);

  Label a, a_end;
  __ Cbz(w19, &a);
  __ B(&a_end);
  __ Bind(&a);
  __ Mov(x4, 1);
  __ Bind(&a_end);

  Label b, b_end;
  __ Cbnz(w19, &b);
  __ B(&b_end);
  __ Bind(&b);
  __ Mov(x5, 1);
  __ Bind(&b_end);

  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
  CHECK_EQUAL_64(1, x4);
  CHECK_EQUAL_64(0, x5);
}

TEST(test_branch) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);
  __ Mov(x3, 0);
  __ Mov(x16, 0xAAAAAAAAAAAAAAAAUL);

  Label bz, bz_end;
  __ Tbz(w16, 0, &bz);
  __ B(&bz_end);
  __ Bind(&bz);
  __ Mov(x0, 1);
  __ Bind(&bz_end);

  Label bo, bo_end;
  __ Tbz(x16, 63, &bo);
  __ B(&bo_end);
  __ Bind(&bo);
  __ Mov(x1, 1);
  __ Bind(&bo_end);

  Label nbz, nbz_end;
  __ Tbnz(x16, 61, &nbz);
  __ B(&nbz_end);
  __ Bind(&nbz);
  __ Mov(x2, 1);
  __ Bind(&nbz_end);

  Label nbo, nbo_end;
  __ Tbnz(w16, 2, &nbo);
  __ B(&nbo_end);
  __ Bind(&nbo);
  __ Mov(x3, 1);
  __ Bind(&nbo_end);
  END();

  RUN();

  CHECK_EQUAL_64(1, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(1, x2);
  CHECK_EQUAL_64(0, x3);
}

namespace {
// Generate a block of code that, when hit, always jumps to `landing_pad`.
void GenerateLandingNops(MacroAssembler* masm, int n, Label* landing_pad) {
  for (int i = 0; i < (n - 1); i++) {
    if (i % 100 == 0) {
      masm->B(landing_pad);
    } else {
      masm->Nop();
    }
  }
  masm->B(landing_pad);
}
}  // namespace

TEST(far_branch_backward) {
  INIT_V8();

  ImmBranchType branch_types[] = {TestBranchType, CompareBranchType,
                                  CondBranchType};

  for (ImmBranchType type : branch_types) {
    int range = Instruction::ImmBranchRange(type);

    SETUP_SIZE(range + 1000 * kInstrSize);

    START();

    Label done, fail;
    // Avoid using near and far as variable name because both are defined as
    // macro in minwindef.h from Windows SDK.
    Label near_label, far_label, in_range, out_of_range;

    __ Mov(x0, 0);
    __ Mov(x1, 1);
    __ Mov(x10, 0);

    __ B(&near_label);
    __ Bind(&in_range);
    __ Orr(x0, x0, 1 << 0);

    __ B(&far_label);
    __ Bind(&out_of_range);
    __ Orr(x0, x0, 1 << 1);

    __ B(&done);

    // We use a slack and an approximate budget instead of checking precisely
    // when the branch limit is hit, since veneers and literal pool can mess
    // with our calculation of where the limit is.
    // In this test, we want to make sure we support backwards branches and the
    // range is more-or-less correct. It's not a big deal if the macro-assembler
    // got the range a little wrong, as long as it's not far off which could
    // affect performance.

    int budget =
        (range - static_cast<int>(__ SizeOfCodeGeneratedSince(&in_range))) /
        kInstrSize;

    const int kSlack = 100;

    // Generate enough code so that the next branch will be in range but we are
    // close to the limit.
    GenerateLandingNops(&masm, budget - kSlack, &fail);

    __ Bind(&near_label);
    switch (type) {
      case TestBranchType:
        __ Tbz(x10, 3, &in_range);
        // This should be:
        //     TBZ <in_range>
        CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      case CompareBranchType:
        __ Cbz(x10, &in_range);
        // This should be:
        //     CBZ <in_range>
        CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      case CondBranchType:
        __ Cmp(x10, 0);
        __ B(eq, &in_range);
        // This should be:
        //     CMP
        //     B.EQ <in_range>
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&near_label));
        break;
      default:
        UNREACHABLE();
    }

    // Now go past the limit so that branches are now out of range.
    GenerateLandingNops(&masm, kSlack * 2, &fail);

    __ Bind(&far_label);
    switch (type) {
      case TestBranchType:
        __ Tbz(x10, 5, &out_of_range);
        // This should be:
        //     TBNZ <skip>
        //     B <out_of_range>
        //   skip:
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      case CompareBranchType:
        __ Cbz(x10, &out_of_range);
        // This should be:
        //     CBNZ <skip>
        //     B <out_of_range>
        //   skip:
        CHECK_EQ(2 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      case CondBranchType:
        __ Cmp(x10, 0);
        __ B(eq, &out_of_range);
        // This should be:
        //     CMP
        //     B.NE <skip>
        //     B <out_of_range>
        //  skip:
        CHECK_EQ(3 * kInstrSize, __ SizeOfCodeGeneratedSince(&far_label));
        break;
      default:
        UNREACHABLE();
    }

    __ Bind(&fail);
    __ Mov(x1, 0);
    __ Bind(&done);

    END();

    RUN();

    CHECK_EQUAL_64(0x3, x0);
    CHECK_EQUAL_64(1, x1);
  }
}

TEST(far_branch_simple_veneer) {
  INIT_V8();

  // Test that the MacroAssembler correctly emits veneers for forward branches
  // to labels that are outside the immediate range of branch instructions.
  int max_range =
    std::max(Instruction::ImmBranchRange(TestBranchType),
             std::max(Instruction::ImmBranchRange(CompareBranchType),
                      Instruction::ImmBranchRange(CondBranchType)));

  SETUP_SIZE(max_range + 1000 * kInstrSize);

  START();

  Label done, fail;
  Label test_tbz, test_cbz, test_bcond;
  Label success_tbz, success_cbz, success_bcond;

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  __ Bind(&test_tbz);
  __ Tbz(x10, 7, &success_tbz);
  __ Bind(&test_cbz);
  __ Cbz(x10, &success_cbz);
  __ Bind(&test_bcond);
  __ Cmp(x10, 0);
  __ B(eq, &success_bcond);

  // Generate enough code to overflow the immediate range of the three types of
  // branches below.
  for (int i = 0; i < max_range / kInstrSize + 1; ++i) {
    if (i % 100 == 0) {
      // If we do land in this code, we do not want to execute so many nops
      // before reaching the end of test (especially if tracing is activated).
      // Also, the branches give the MacroAssembler the opportunity to emit the
      // veneers.
      __ B(&fail);
    } else {
      __ Nop();
    }
  }
  __ B(&fail);

  __ Bind(&success_tbz);
  __ Orr(x0, x0, 1 << 0);
  __ B(&test_cbz);
  __ Bind(&success_cbz);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_bcond);
  __ Bind(&success_bcond);
  __ Orr(x0, x0, 1 << 2);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x7, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(far_branch_veneer_link_chain) {
  INIT_V8();

  // Test that the MacroAssembler correctly emits veneers for forward branches
  // that target out-of-range labels and are part of multiple instructions
  // jumping to that label.
  //
  // We test the three situations with the different types of instruction:
  // (1)- When the branch is at the start of the chain with tbz.
  // (2)- When the branch is in the middle of the chain with cbz.
  // (3)- When the branch is at the end of the chain with bcond.
  int max_range =
    std::max(Instruction::ImmBranchRange(TestBranchType),
             std::max(Instruction::ImmBranchRange(CompareBranchType),
                      Instruction::ImmBranchRange(CondBranchType)));

  SETUP_SIZE(max_range + 1000 * kInstrSize);

  START();

  Label skip, fail, done;
  Label test_tbz, test_cbz, test_bcond;
  Label success_tbz, success_cbz, success_bcond;

  __ Mov(x0, 0);
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  __ B(&skip);
  // Branches at the start of the chain for situations (2) and (3).
  __ B(&success_cbz);
  __ B(&success_bcond);
  __ Nop();
  __ B(&success_bcond);
  __ B(&success_cbz);
  __ Bind(&skip);

  __ Bind(&test_tbz);
  __ Tbz(x10, 7, &success_tbz);
  __ Bind(&test_cbz);
  __ Cbz(x10, &success_cbz);
  __ Bind(&test_bcond);
  __ Cmp(x10, 0);
  __ B(eq, &success_bcond);

  skip.Unuse();
  __ B(&skip);
  // Branches at the end of the chain for situations (1) and (2).
  __ B(&success_cbz);
  __ B(&success_tbz);
  __ Nop();
  __ B(&success_tbz);
  __ B(&success_cbz);
  __ Bind(&skip);

  // Generate enough code to overflow the immediate range of the three types of
  // branches below.
  GenerateLandingNops(&masm, (max_range / kInstrSize) + 1, &fail);

  __ Bind(&success_tbz);
  __ Orr(x0, x0, 1 << 0);
  __ B(&test_cbz);
  __ Bind(&success_cbz);
  __ Orr(x0, x0, 1 << 1);
  __ B(&test_bcond);
  __ Bind(&success_bcond);
  __ Orr(x0, x0, 1 << 2);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x7, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(far_branch_veneer_broken_link_chain) {
  INIT_V8();

  // Check that the MacroAssembler correctly handles the situation when removing
  // a branch from the link chain of a label and the two links on each side of
  // the removed branch cannot be linked together (out of range).
  //
  // We want to generate the following code, we test with tbz because it has a
  // small range:
  //
  // ~~~
  // 1: B <far>
  //          :
  //          :
  //          :
  // 2: TBZ <far> -------.
  //          :          |
  //          :          | out of range
  //          :          |
  // 3: TBZ <far>        |
  //          |          |
  //          | in range |
  //          V          |
  // far:              <-'
  // ~~~
  //
  // If we say that the range of TBZ is 3 lines on this graph, then we can get
  // into a situation where the link chain gets broken. When emitting the two
  // TBZ instructions, we are in range of the previous branch in the chain so
  // we'll generate a TBZ and not a TBNZ+B sequence that can encode a bigger
  // range.
  //
  // However, the first TBZ (2), is out of range of the far label so a veneer
  // will be generated after the second TBZ (3). And this will result in a
  // broken chain because we can no longer link from (3) back to (1).
  //
  // ~~~
  // 1: B <far>     <-.
  //                  :
  //                  : out of range
  //                  :
  // 2: TBZ <veneer>  :
  //                  :
  //                  :
  //                  :
  // 3: TBZ <far> ----'
  //
  //    B <skip>
  // veneer:
  //    B <far>
  // skip:
  //
  // far:
  // ~~~
  //
  // This test makes sure the MacroAssembler is able to resolve this case by,
  // for instance, resolving (1) early and making it jump to <veneer> instead of
  // <far>.

  int max_range = Instruction::ImmBranchRange(TestBranchType);
  int inter_range = max_range / 2 + max_range / 10;

  SETUP_SIZE(3 * inter_range + 1000 * kInstrSize);

  START();

  Label fail, done;
  Label test_1, test_2, test_3;
  Label far_target;

  __ Mov(x0, 0);  // Indicates the origin of the branch.
  __ Mov(x1, 1);
  __ Mov(x10, 0);

  // First instruction in the label chain.
  __ Bind(&test_1);
  __ Mov(x0, 1);
  __ B(&far_target);

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  // Will need a veneer to point to reach the target.
  __ Bind(&test_2);
  __ Mov(x0, 2);
  {
    Label tbz;
    __ Bind(&tbz);
    __ Tbz(x10, 7, &far_target);
    // This should be a single TBZ since the previous link is in range at this
    // point.
    CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&tbz));
  }

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  // Does not need a veneer to reach the target, but the initial branch
  // instruction is out of range.
  __ Bind(&test_3);
  __ Mov(x0, 3);
  {
    Label tbz;
    __ Bind(&tbz);
    __ Tbz(x10, 7, &far_target);
    // This should be a single TBZ since the previous link is in range at this
    // point.
    CHECK_EQ(1 * kInstrSize, __ SizeOfCodeGeneratedSince(&tbz));
  }

  // A veneer will be generated for the first TBZ, which will then remove the
  // label from the chain and break it because the second TBZ is out of range of
  // the first branch.
  // The MacroAssembler should be able to cope with this.

  GenerateLandingNops(&masm, inter_range / kInstrSize, &fail);

  __ B(&fail);

  __ Bind(&far_target);
  __ Cmp(x0, 1);
  __ B(eq, &test_2);
  __ Cmp(x0, 2);
  __ B(eq, &test_3);

  __ B(&done);
  __ Bind(&fail);
  __ Mov(x1, 0);
  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x3, x0);
  CHECK_EQUAL_64(0x1, x1);
}

TEST(branch_type) {
  INIT_V8();

  SETUP();

  Label fail, done;

  START();
  __ Mov(x0, 0x0);
  __ Mov(x10, 0x7);
  __ Mov(x11, 0x0);

  // Test non taken branches.
  __ Cmp(x10, 0x7);
  __ B(&fail, ne);
  __ B(&fail, never);
  __ B(&fail, reg_zero, x10);
  __ B(&fail, reg_not_zero, x11);
  __ B(&fail, reg_bit_clear, x10, 0);
  __ B(&fail, reg_bit_set, x10, 3);

  // Test taken branches.
  Label l1, l2, l3, l4, l5;
  __ Cmp(x10, 0x7);
  __ B(&l1, eq);
  __ B(&fail);
  __ Bind(&l1);
  __ B(&l2, always);
  __ B(&fail);
  __ Bind(&l2);
  __ B(&l3, reg_not_zero, x10);
  __ B(&fail);
  __ Bind(&l3);
  __ B(&l4, reg_bit_clear, x10, 15);
  __ B(&fail);
  __ Bind(&l4);
  __ B(&l5, reg_bit_set, x10, 1);
  __ B(&fail);
  __ Bind(&l5);

  __ B(&done);

  __ Bind(&fail);
  __ Mov(x0, 0x1);

  __ Bind(&done);

  END();

  RUN();

  CHECK_EQUAL_64(0x0,
"""


```