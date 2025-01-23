Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-assembler-arm64.cc`. The summary should include:

1. **General Functionality:** What does the code do?
2. **Torque Source Check:** Does the filename ending in `.tq` imply it's a Torque source?
3. **JavaScript Relationship:** Is there a connection to JavaScript functionality? If so, provide a JavaScript example.
4. **Code Logic Inference:** Are there any test cases with clear inputs and expected outputs that can be reasoned about?
5. **Common Programming Errors:** Does the code demonstrate or test for any common programming mistakes?
6. **Overall Summary (Part 12 of 15):**  Given this is part 12 of 15, what is the overarching purpose of this section?

Let's break down the code to address each point.

**Code Analysis:**

The code consists of multiple `TEST` functions. Each `TEST` function seems to be testing a specific aspect of the ARM64 assembler within the V8 engine. The names of the tests are quite descriptive:

* `adds_ands_bics_subs`: Tests the `adds`, `ands`, `bics`, and `subs` instructions with the zero register (`xzr`) as the destination.
* `register_bit`: Tests the `bits()` method of the `RegList` class, verifying the bit representation of different registers.
* `peek_poke_simple`, `peek_poke_unaligned`, `peek_poke_endianness`, `peek_poke_mixed`: Test the `Poke` (write to stack) and `Peek` (read from stack) instructions, focusing on different scenarios like aligned/unaligned access, endianness, and mixing with other stack operations.
* `push_pop_simple_32`, `push_pop_simple_64`, `push_pop_fp_simple_32`, `push_pop_fp_simple_64`: Test the `Push` and `Pop` instructions for integer and floating-point registers with different sizes and methods.
* `push_pop_mixed_methods_64`: Tests a mix of `Push`/`Pop` and `PushSizeRegList`/`PopSizeRegList`.
* `push_pop`: Tests various combinations of `Push` and `Pop` with register lists.
* `copy_slots_down`, `copy_slots_up`, `copy_double_words_downwards_even`, `copy_double_words_downwards_odd`, `copy_noop`: Test the `CopySlots` and `CopyDoubleWords` instructions for moving data on the stack.
* `noreg`, `vreg`: Test properties and helper functions related to `NoReg` and `VRegister`.

**Addressing the User's Requirements:**

1. **Functionality:** The code tests the functionality of the ARM64 assembler in V8. It focuses on verifying the correct behavior of various assembly instructions, especially those related to register manipulation, stack operations (push, pop, peek, poke), and memory copying.

2. **Torque Source Check:** The prompt explicitly states the condition for a Torque source: if the filename ends with `.tq`. Since the filename is `test-assembler-arm64.cc`, it is **not** a Torque source.

3. **JavaScript Relationship:** Assembler code directly relates to how JavaScript code is compiled and executed at a low level. The instructions tested here are the building blocks for implementing JavaScript operations.

4. **Code Logic Inference:** Many tests have clear initialization and checks. For example, in `peek_poke_simple`:
   * **Assumption:** `literal_base` is a specific value.
   * **Input:** Registers `x0` to `x3` are initialized with multiples of `literal_base`.
   * **Action:** Values from these registers are written to the stack using `Poke` and then read back into `w10` to `w13` using `Peek`.
   * **Output:** `x0` to `x3` should retain their original values, and `w10` to `w13` should contain the lower 32 bits of the original `x0` to `x3`.

5. **Common Programming Errors:**  The `peek_poke_unaligned` test directly targets a common programming error: **unaligned memory access**. Accessing memory at addresses that are not multiples of the data size can lead to crashes or unexpected behavior on some architectures. This test verifies that the assembler handles unaligned accesses correctly.

6. **Overall Summary (Part 12 of 15):**  Given that this is part 12 of a series of tests for the ARM64 assembler, this section likely focuses on **testing stack manipulation instructions and memory copying operations**. It builds upon the fundamental register operations tested in earlier parts and prepares for more complex scenarios involving function calls, object allocation, etc., which might be covered in subsequent parts.
这是 `v8/test/cctest/test-assembler-arm64.cc` 源代码的一部分，它专注于测试 **V8 JavaScript 引擎中 ARM64 架构汇编器的功能**。

**功能列举:**

这个代码片段主要测试了 ARM64 汇编器的以下几个方面的功能：

1. **条件标志操作指令 (Adds, Ands, Bics, Subs with flags):**  测试了 `adds`, `ands`, `bics`, `subs` 指令在将结果写入零寄存器 (`xzr`) 时设置条件标志的行为。尽管结果被丢弃，但条件标志仍然会被更新。

2. **寄存器位操作 (`register_bit`):**  测试了 `RegList` 类中获取寄存器位掩码的功能，确保能够正确获取不同寄存器的位表示，包括通用寄存器、特殊用途寄存器 (如帧指针 `fp`, 链接寄存器 `lr`, 零寄存器 `xzr`, 栈指针 `sp`)。

3. **栈 Peek 和 Poke 操作 (`peek_poke_*`):**  测试了向栈中写入数据 (`Poke`) 和从栈中读取数据 (`Peek`) 的功能。这些测试涵盖了：
    * **简单读写 (`peek_poke_simple`):**  对齐的 64 位和 32 位数据的读写。
    * **非对齐读写 (`peek_poke_unaligned`):** 测试非 8 字节边界的读写。
    * **字节序 (`peek_poke_endianness`):**  验证在进行栈读写时是否考虑了系统的字节序。
    * **与其他栈操作混合 (`peek_poke_mixed`):**  测试 `Peek` 和 `Poke` 与 `Push` 和 `Pop` 等其他栈操作混合使用时的行为。

4. **栈 Push 和 Pop 操作 (`push_pop_*`):**  测试了将寄存器值压入栈 (`Push`) 和从栈中弹出值到寄存器 (`Pop`) 的功能。测试涵盖了：
    * **简单 Push/Pop (`push_pop_simple_32`, `push_pop_simple_64`, `push_pop_fp_simple_32`, `push_pop_fp_simple_64`):**  分别测试 32 位通用寄存器、64 位通用寄存器、32 位浮点寄存器和 64 位浮点寄存器的 Push 和 Pop 操作，并使用不同的 Push/Pop 方法（一次 Push/Pop 多个寄存器或使用寄存器列表）。
    * **混合 Push/Pop 方法 (`push_pop_mixed_methods_64`):** 测试混合使用一次 Push/Pop 多个寄存器和使用寄存器列表进行 Push/Pop 的情况。
    * **各种 Push/Pop 组合 (`push_pop`):** 测试更复杂的 Push 和 Pop 操作序列，包括压入和弹出不同数量和类型的寄存器。

5. **栈数据复制操作 (`copy_slots_down`, `copy_slots_up`, `copy_double_words_downwards_*`, `copy_noop`):** 测试了在栈上复制数据的指令：
    * **`CopySlots`:**  以 Slot (8 字节) 为单位在栈上向上或向下复制数据。
    * **`CopyDoubleWords`:** 以双字 (16 字节) 为单位在栈上向下复制数据，并考虑了源地址小于目标地址的情况。
    * **`copy_noop`:** 测试复制 0 个 Slot 的情况，验证指令是否不会产生副作用。

6. **`NoReg` 和 `VReg` 相关测试 (`noreg`, `vreg`):**
    * **`noreg`:** 验证 `NoReg` 常量的属性，例如它等于 `NoVReg` 和 `NoCPUReg`，并且 `IsNone()` 返回 true。
    * **`vreg`:** 测试与浮点寄存器 (`VRegister`) 相关的辅助函数，例如根据寄存器格式获取大小 (`RegisterSizeInBitsFromFormat`)。

**关于 .tq 结尾:**

如果 `v8/test/cctest/test-assembler-arm64.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是一种用于在 V8 中定义运行时内置函数和编译器优化的领域特定语言。由于当前文件名是 `.cc`，因此它是 C++ 源代码。

**与 JavaScript 的关系 (举例):**

这些汇编指令是 JavaScript 代码在底层执行的基础。例如，JavaScript 中的加法运算 `a + b` 可能在 ARM64 架构上被编译成类似 `adds x0, x1, x2` 的汇编指令，其中 `x0` 存储结果，`x1` 和 `x2` 存储 `a` 和 `b` 的值。

栈操作与 JavaScript 的函数调用和局部变量管理密切相关。例如，当 JavaScript 函数被调用时，参数和局部变量会被压入栈中 (`Push`)，函数执行完毕后会被弹出 (`Pop`)。`Peek` 和 `Poke` 可以在某些需要直接操作内存的场景中使用。

```javascript
// JavaScript 加法运算
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result); // 输出 8
```

在 V8 的 ARM64 汇编实现中，`add(5, 3)` 的执行可能涉及 `adds` 指令。

**代码逻辑推理 (假设输入与输出):**

以 `peek_poke_simple` 中的部分代码为例：

**假设输入:**

* `literal_base = 0x0100001000100101UL`
* 寄存器 `x0` 初始化为 `literal_base * 1 = 0x0100001000100101`
* 寄存器 `x1` 初始化为 `literal_base * 2 = 0x0200002000200202`
* 寄存器 `x2` 初始化为 `literal_base * 3 = 0x0300003000300303`
* 寄存器 `x3` 初始化为 `literal_base * 4 = 0x0400004000400404`

**执行的操作:**

```assembly
  __ Poke(x0, 0); // 将 x0 的值写入栈偏移 0
  __ Poke(x1, 8); // 将 x1 的值写入栈偏移 8
  __ Poke(x2, 16); // 将 x2 的值写入栈偏移 16
  __ Poke(x3, 24); // 将 x3 的值写入栈偏移 24
  Clobber(&masm, x0_to_x3); // 模拟 x0-x3 的值被修改
  __ Peek(x0, 0); // 从栈偏移 0 读取值到 x0
  __ Peek(x1, 8); // 从栈偏移 8 读取值到 x1
  __ Peek(x2, 16); // 从栈偏移 16 读取值到 x2
  __ Peek(x3, 24); // 从栈偏移 24 读取值到 x3
```

**预期输出:**

* 寄存器 `x0` 的值应为 `0x0100001000100101`
* 寄存器 `x1` 的值应为 `0x0200002000200202`
* 寄存器 `x2` 的值应为 `0x0300003000300303`
* 寄存器 `x3` 的值应为 `0x0400004000400404`

**用户常见的编程错误 (举例):**

* **非对齐内存访问:**  在没有正确处理的情况下，尝试访问非对齐的内存地址会导致程序崩溃或产生不可预测的结果。`peek_poke_unaligned` 测试正是为了验证汇编器在这种情况下是否能正确工作。用户可能会错误地假设所有内存访问都是原子且不考虑对齐的。
  ```c++
  // C++ 中可能导致问题的代码，在某些架构上
  uint32_t* ptr = (uint32_t*)((char*)buffer + 1); // ptr 指向非 4 字节对齐的地址
  uint32_t value = *ptr; // 可能会崩溃或读取错误的值
  ```

* **栈溢出:**  过度使用栈空间，例如在深度递归的函数调用中，可能导致栈溢出。虽然这里的测试没有直接模拟栈溢出，但 `Push` 和 `Pop` 操作的错误使用可能会导致栈指针错误，从而引发类似的问题。

* **寄存器使用错误:**  错误地假设寄存器的值或在没有保存和恢复的情况下覆盖了重要寄存器的值。例如，在函数调用前后，某些寄存器的值必须被保留。

**归纳其功能 (作为第 12 部分):**

作为测试套件的第 12 部分，这个代码片段主要集中在 **测试 ARM64 汇编器中处理栈和内存操作的指令**。它深入测试了 `Push`、`Pop`、`Peek`、`Poke` 以及栈内存复制等关键指令的正确性，涵盖了各种不同的使用场景，包括数据大小、对齐方式、字节序以及与其他指令的组合。这部分测试对于确保 V8 引擎在 ARM64 架构上正确管理内存和执行 JavaScript 代码至关重要。它很可能建立在之前测试了更基础的算术和逻辑指令的基础上，并为后续测试更复杂的控制流和函数调用等功能做准备。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
e flags in these forms,
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