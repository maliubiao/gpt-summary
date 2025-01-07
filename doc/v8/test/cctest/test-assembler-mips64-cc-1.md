Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Initial Understanding and Goal:**

The request asks for an analysis of a C++ code snippet from V8's test suite. The core goal is to understand what this specific part of the test file does. Key aspects to identify include:

* **Overall Functionality:** What is being tested?
* **Relevance to JavaScript:** Does this test anything directly related to JavaScript behavior?
* **Code Logic and Examples:** Can we infer the test's purpose from the code and provide illustrative examples?
* **Common Programming Errors:** Does the code implicitly or explicitly touch on potential user errors?
* **Summary:** Condense the findings.

**2. Deconstructing the Code Snippet:**

The provided code is a series of test cases (functions starting with `TEST(...)`) within a C++ file. The filename `test-assembler-mips64.cc` immediately suggests it's testing the MIPS64 assembler within V8. The `CcTest::InitializeVM()` and `Isolate* isolate = CcTest::i_isolate();` lines confirm this is a V8 internal test.

* **Individual Test Cases (`TEST(MIPS...)`):** Each `TEST` block seems to focus on testing specific MIPS64 assembly instructions or combinations thereof. The names like `TEST(MIPS12)`, `TEST(MIPS13)`, etc., suggest sequential testing of different features.

* **`MacroAssembler`:** The `MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);` line indicates that the tests are generating MIPS64 machine code dynamically.

* **Assembly Instructions (`__ Pop()`, `__ addu()`, `__ Sw()`, `__ Lw()`, etc.):** The core of each test involves emitting sequences of MIPS64 assembly instructions. These instructions are the building blocks being validated.

* **Data Structures (`struct T`)**:  The `struct T` definitions within some tests define memory layouts used for testing load/store operations. They simulate data in memory.

* **Code Generation and Execution:** The `assm.GetCode(...)`, `Factory::CodeBuilder(...)`, and `f.Call(...)` lines demonstrate the process of generating the assembly code, creating a callable function from it, and then executing that generated code.

* **Assertions (`CHECK_EQ(...)`, `CHECK(...)`):** The `CHECK_EQ` and `CHECK` macros are used to verify the expected outcomes of the executed assembly code. This is how the tests determine if the assembler and the generated code are working correctly.

**3. Inferring Functionality from Specific Tests:**

* **`TEST(MIPS12)`:** The sequence of `push`, `pop`, `Sw`, `Lw` instructions, along with the `offsetof` usage, points towards testing stack manipulation and memory access (store and load) using offsets within a structure. The "appear after opt" and "disappear after opt" comments suggest it might also be testing assembler optimizations.

* **`TEST(MIPS13)`:** The `Cvt_d_uw` and `Trunc_uw_d` macros clearly indicate this test focuses on conversions between unsigned words (32-bit integers) and double-precision floating-point numbers.

* **`TEST(MIPS14)`:**  The `ROUND_STRUCT_ELEMENT` macro and the `round_w_d`, `floor_w_d`, `ceil_w_d`, `trunc_w_d`, and `cvt_w_d` instructions strongly suggest this test is validating various rounding and conversion operations for floating-point numbers. The FCSR (Floating-Point Control and Status Register) manipulation reinforces this.

* **`TEST(MIPS16)`:** The names `Lw`, `Sw`, `Lwu`, `Lh`, `Sh`, `Lb` and the use of `int64_t` in the `struct T` clearly indicate testing different sizes and signedness of memory load and store operations (word, half-word, byte, signed/unsigned).

* **Tests with `if (kArchVariant == kMips64r6)`:** These tests are specifically for the MIPS64 Release 6 architecture, indicating they're testing instructions or features specific to that revision (like `seleqz`, `selnez`, `min_d`, `max_d`, `rint_d`, `sel`).

**4. Connecting to JavaScript (If Applicable):**

While these are low-level assembler tests, they underpin the functionality of JavaScript. For example:

* **Floating-point conversions and rounding (MIPS13, MIPS14, `rint_d`, `rint_s`):** JavaScript numbers are often represented as doubles. The tested instructions are used when JavaScript code performs operations that require converting between integers and floating-point values or when rounding numbers.
* **Memory access (MIPS12, MIPS16):** When JavaScript objects are accessed or variables are manipulated, the underlying engine uses load and store instructions to read and write data in memory.

**5. Code Logic, Inputs, and Outputs:**

For tests like MIPS13 and MIPS14, it's possible to infer the expected behavior based on the operations being performed. The `CHECK_EQ` statements provide explicit input/output checks. For instance, in MIPS13, the test sets `t.cvt_big_in` to `0xFFFFFFFF` and checks if `t.cvt_big_out` becomes the double representation of that unsigned integer.

**6. Identifying Potential Programming Errors:**

The memory load/store tests (MIPS16) implicitly highlight potential errors like:

* **Endianness issues:** The checks based on `kArchEndian` show how the interpretation of byte order can differ.
* **Signed vs. unsigned interpretation:** Loading a signed value into an unsigned register (or vice-versa) can lead to unexpected results.
* **Data truncation:**  Storing a larger value into a smaller memory location (e.g., storing a 32-bit value into a 16-bit location) will result in data loss.

**7. Structuring the Response:**

Organize the findings logically, starting with the general purpose of the file, then detailing the functionality of specific tests, and finally addressing the other points requested (JavaScript relevance, code logic, errors, summary). Use clear and concise language.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just testing assembly instructions."
* **Refinement:** "Yes, but it's testing *specific* assembly instructions related to memory, floating-point conversions, rounding, and architecture-specific features."
* **Initial thought:** "How does this relate to JavaScript?"
* **Refinement:** "Indirectly, it ensures the low-level building blocks used by the JavaScript engine are working correctly."
* **Considering the "appears after opt" comments:** Realize this test also includes aspects of assembler optimization verification.

By following this breakdown, analyzing the code snippets, and thinking about the underlying principles of assembly programming and the V8 JavaScript engine, we can generate a comprehensive and accurate response.
好的，让我们来分析一下这段v8源代码的功能。

**整体功能归纳**

这段代码是 `v8/test/cctest/test-assembler-mips64.cc` 文件的一部分，这个文件专门用于测试 **MIPS64 架构下的汇编器 (Assembler)** 的功能。它通过编写一系列小的汇编代码片段，然后在V8环境中执行这些代码，并使用断言 (`CHECK_EQ`, `CHECK`) 来验证汇编器的指令生成和代码执行结果是否符合预期。

**具体功能分解**

这段代码包含了多个独立的测试用例，每个 `TEST(MIPS...)` 函数代表一个测试用例。以下是每个测试用例的功能分解：

* **`TEST(MIPS12)`:**
    * **核心功能:** 测试在汇编代码优化前后，某些指令是否会被正确移除或保留。
    * **测试点:**  `Pop()`, `push()`, `nop()` 指令在优化过程中的行为，以及 `Sw` (Store Word) 和 `Lw` (Load Word) 指令的基本内存操作。
    * **优化验证:** 通过注释 "appear after opt." 和 "These instructions disappear after opt."  来标记在代码优化过程中应该出现或消失的指令。

* **`TEST(MIPS13)`:**
    * **核心功能:** 测试 **无符号字 (unsigned word)** 与 **双精度浮点数 (double)** 之间的转换指令 (`Cvt_d_uw`) 以及截断指令 (`Trunc_uw_d`)。

* **`TEST(MIPS14)`:**
    * **核心功能:** 测试各种浮点数 **舍入 (rounding)** 和 **转换 (conversion)** 指令，包括 `round_w_d` (四舍五入), `floor_w_d` (向下取整), `ceil_w_d` (向上取整), `trunc_w_d` (向零取整), `cvt_w_d` (转换到字)。
    * **FPU异常处理:** 涉及到浮点单元 (FPU) 的控制状态寄存器 (FCSR) 的设置和检查，用于验证在不同舍入模式下，以及在遇到 NaN 等特殊值时，指令的行为和异常标志是否正确。

* **`TEST(MIPS15)`:**
    * **核心功能:** 测试 **标签 (Label)** 在汇编指令中的正确使用，特别是当一个标签在多个指令中被引用时，汇编器是否能正确处理。

* **`TEST(MIPS16)`:**
    * **核心功能:** 测试 MIPS64 架构下的各种 **64位内存加载和存储指令**，包括不同大小 (字、半字、字节) 和有无符号的加载 (`Lw`, `Lwu`, `Lh`, `Lhu`, `Lb`) 和存储 (`Sw`, `Sh`) 指令。
    * **字节序 (Endianness) 考虑:** 代码中使用了 `if (kArchEndian == kLittle)` 来根据系统字节序进行不同的结果验证。

* **`TEST(seleqz_selnez)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:** 测试 MIPS64 Release 6 中新增的 **条件选择指令** `seleqz` (当第二个操作数为零时选择) 和 `selnez` (当第二个操作数非零时选择)，包括对整数和浮点数的支持。

* **`TEST(min_max)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:** 测试 MIPS64 Release 6 中新增的 **最小值 (`min_d`, `min_s`) 和最大值 (`max_d`, `max_s`) 指令**，用于比较浮点数。测试了包括 NaN 和无穷大在内的特殊情况。

* **`TEST(rint_d)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:** 测试 MIPS64 Release 6 中新增的 **浮点数舍入到整数指令 `rint_d` (round to integer)**，并验证在不同的 FPU 舍入模式下，指令的执行结果是否正确。

* **`TEST(sel)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:** 测试 MIPS64 Release 6 中新增的 **条件选择指令 `sel_d` 和 `sel_s`**，根据第一个操作数的符号位来选择第二个或第三个操作数。

* **`TEST(rint_s)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:**  类似于 `TEST(rint_d)`，但测试的是 **单精度浮点数 (float)** 的舍入到整数指令 `rint_s`。

* **`TEST(mina_maxa)`:** (仅在 `kArchVariant == kMips64r6` 时执行)
    * **核心功能:** 测试 MIPS64 Release 6 中新增的 **绝对值最小值 (`mina_d`, `mina_s`) 和绝对值最大值 (`maxa_d`, `maxa_s`) 指令**，用于比较浮点数的绝对值。

**关于文件后缀 `.tq`**

根据描述，如果 `v8/test/cctest/test-assembler-mips64.cc` 以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码**。 Torque 是一种 V8 内部使用的类型化的汇编语言，用于生成高效的 JavaScript 内置函数。  然而，当前提供的文件后缀是 `.cc`，表明它是 **C++ 源代码**，直接使用 V8 的 `MacroAssembler` 来生成汇编代码。

**与 JavaScript 的关系及示例**

尽管这些测试是针对底层的汇编器，但它们直接关系到 V8 如何执行 JavaScript 代码。例如：

* **浮点数运算 (MIPS13, MIPS14, `rint_d`, `rint_s`, `min_max` 等):** JavaScript 中的 `Math.round()`, `Math.floor()`, `Math.ceil()`, `Math.trunc()`, `Math.min()`, `Math.max()` 等函数在底层实现时，可能会用到这里测试的 MIPS64 浮点数指令。

   ```javascript
   // JavaScript 示例
   console.log(Math.round(3.7));   // 输出 4
   console.log(Math.floor(3.7));   // 输出 3
   console.log(Math.ceil(3.2));    // 输出 4
   console.log(Math.trunc(-3.7));  // 输出 -3
   console.log(Math.min(10, 5));   // 输出 5
   console.log(Math.max(10, 5));   // 输出 10
   ```

* **整数和浮点数之间的转换 (MIPS13):**  当 JavaScript 进行类型转换时，例如将数字转换为整数，或者进行涉及不同数值类型的运算时，可能会用到这些指令。

   ```javascript
   // JavaScript 示例
   let num = 3.14;
   let intNum = parseInt(num); // 输出 3，底层可能用到截断指令
   let floatNum = 10;
   let doubleNum = parseFloat(floatNum); // 输出 10，底层可能涉及到转换
   ```

* **内存操作 (MIPS16):**  JavaScript 对象的属性访问、数组元素的读写等操作，在 V8 的底层都需要通过加载和存储指令来完成。

   ```javascript
   // JavaScript 示例
   let obj = { x: 10, y: 20 };
   console.log(obj.x); // 读取属性 x，底层可能用到加载指令
   obj.y = 25;       // 修改属性 y，底层可能用到存储指令
   ```

**代码逻辑推理、假设输入与输出**

以 `TEST(MIPS13)` 为例：

**假设输入 `t` 的初始状态：**
```c++
T t;
t.cvt_big_in = 0xFFFFFFFF;
t.cvt_small_in  = 333;
```

**汇编代码执行逻辑：**
1. 将 `t.cvt_small_in` 的值 (333) 加载到寄存器 `a4`。
2. 使用 `Cvt_d_uw` 指令将 `a4` 中的无符号整数转换为双精度浮点数，结果存储到浮点寄存器 `f10`。
3. 将 `f10` 中的双精度浮点数存储到 `t.cvt_small_out`。
4. 使用 `Trunc_uw_d` 指令将 `f10` 中的双精度浮点数截断为无符号整数，结果存储到 `f10`。
5. 将 `f10` 中的无符号整数存储到 `t.trunc_small_out`。
6. 对 `t.cvt_big_in` 执行类似的操作。

**预期输出 (部分):**

```c++
CHECK_EQ(t.cvt_big_out, static_cast<double>(t.cvt_big_in)); // t.cvt_big_out 应该是 4294967295.0
CHECK_EQ(t.cvt_small_out, static_cast<double>(t.cvt_small_in)); // t.cvt_small_out 应该是 333.0
CHECK_EQ(static_cast<int>(t.trunc_big_out), static_cast<int>(t.cvt_big_in)); // t.trunc_big_out 应该是 4294967295
CHECK_EQ(static_cast<int>(t.trunc_small_out), static_cast<int>(t.cvt_small_in)); // t.trunc_small_out 应该是 333
```

**涉及用户常见的编程错误**

* **字节序问题 (Endianness):** 在 `TEST(MIPS16)` 中体现，如果用户在不同字节序的系统之间传递二进制数据，可能会因为对字节的解释不同而导致数据错误。V8 的测试中会考虑到这种情况。

* **有符号和无符号类型的混淆:**  在 `TEST(MIPS16)` 中测试了有符号和无符号的加载，用户在 C/C++ 中如果不注意数据类型，可能会将有符号数误认为无符号数，或者反之，导致数值超出预期范围或解释错误。

   ```c++
   // C++ 示例
   unsigned int positive_num = 0xFFFFFFFF;
   int negative_representation = static_cast<int>(positive_num); // 结果将是 -1

   int negative_num = -10;
   unsigned int unsigned_representation = static_cast<unsigned int>(negative_num); // 结果将是一个很大的正数
   ```

* **浮点数精度问题:** 虽然没有直接在提供的代码片段中体现，但在进行浮点数运算和比较时，由于浮点数的表示方式，可能会出现精度损失。用户需要注意不要直接使用 `==` 来比较浮点数，而是应该使用一个小的误差范围。

* **未初始化的内存:** 虽然测试代码会初始化数据结构，但实际编程中，访问未初始化的内存会导致不可预测的行为。

**总结第2部分的功能**

这段代码的第2部分 (以提供的代码片段为准) 主要专注于测试 MIPS64 架构下汇编器的以下功能：

* **指令优化:** 验证汇编器在优化过程中对特定指令的处理。
* **无符号整数与双精度浮点数之间的转换和截断。**
* **各种浮点数舍入和转换指令，以及相关的 FPU 异常处理。**
* **标签在汇编代码中的正确使用。**
* **不同大小和符号类型的 64 位内存加载和存储指令，并考虑了字节序。**
* **MIPS64 Release 6 特有的条件选择、最小值/最大值、绝对值最小值/最大值以及浮点数舍入到整数指令。**

总而言之，这段代码是 V8 保证其在 MIPS64 架构上正确运行的关键组成部分，它细致地测试了汇编器的各种功能，确保生成的机器码能够按照预期执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共13部分，请归纳一下它的功能

"""
appear after opt.
  __ Pop();
  __ addu(a4, a4, a4);
  __ nop();
  __ Pop();     // These instructions disappear after opt.
  __ push(a7);
  __ nop();
  __ push(a7);  // These instructions disappear after opt.
  __ pop(a7);
  __ nop();
  __ push(a7);
  __ pop(t0);
  __ nop();
  __ Sw(a4, MemOperand(fp, offsetof(T, y)));
  __ Lw(a4, MemOperand(fp, offsetof(T, y)));
  __ nop();
  __ Sw(a4, MemOperand(fp, offsetof(T, y)));
  __ Lw(a5, MemOperand(fp, offsetof(T, y)));
  __ nop();
  __ push(a5);
  __ Lw(a5, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a6);
  __ nop();
  __ push(a6);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a5);
  __ nop();
  __ push(a5);
  __ Lw(a6, MemOperand(fp, offsetof(T, y)));
  __ pop(a7);
  __ nop();

  __ mov(fp, t2);
  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.x = 1;
  t.y = 2;
  t.y1 = 3;
  t.y2 = 4;
  t.y3 = 0XBABA;
  t.y4 = 0xDEDA;

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(3, t.y1);
}


TEST(MIPS13) {
  // Test Cvt_d_uw and Trunc_uw_d macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    double cvt_big_out;
    double cvt_small_out;
    uint32_t trunc_big_out;
    uint32_t trunc_small_out;
    uint32_t cvt_big_in;
    uint32_t cvt_small_in;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  __ Sw(a4, MemOperand(a0, offsetof(T, cvt_small_in)));
  __ Cvt_d_uw(f10, a4);
  __ Sdc1(f10, MemOperand(a0, offsetof(T, cvt_small_out)));

  __ Trunc_uw_d(f10, f10, f4);
  __ Swc1(f10, MemOperand(a0, offsetof(T, trunc_small_out)));

  __ Sw(a4, MemOperand(a0, offsetof(T, cvt_big_in)));
  __ Cvt_d_uw(f8, a4);
  __ Sdc1(f8, MemOperand(a0, offsetof(T, cvt_big_out)));

  __ Trunc_uw_d(f8, f8, f4);
  __ Swc1(f8, MemOperand(a0, offsetof(T, trunc_big_out)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.cvt_big_in = 0xFFFFFFFF;
  t.cvt_small_in  = 333;

  f.Call(&t, 0, 0, 0, 0);

  CHECK_EQ(t.cvt_big_out, static_cast<double>(t.cvt_big_in));
  CHECK_EQ(t.cvt_small_out, static_cast<double>(t.cvt_small_in));

  CHECK_EQ(static_cast<int>(t.trunc_big_out), static_cast<int>(t.cvt_big_in));
  CHECK_EQ(static_cast<int>(t.trunc_small_out),
           static_cast<int>(t.cvt_small_in));
}


TEST(MIPS14) {
  // Test round, floor, ceil, trunc, cvt.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

#define ROUND_STRUCT_ELEMENT(x) \
  uint32_t x##_isNaN2008; \
  int32_t x##_up_out; \
  int32_t x##_down_out; \
  int32_t neg_##x##_up_out; \
  int32_t neg_##x##_down_out; \
  uint32_t x##_err1_out; \
  uint32_t x##_err2_out; \
  uint32_t x##_err3_out; \
  uint32_t x##_err4_out; \
  int32_t x##_invalid_result;

  struct T {
    double round_up_in;
    double round_down_in;
    double neg_round_up_in;
    double neg_round_down_in;
    double err1_in;
    double err2_in;
    double err3_in;
    double err4_in;

    ROUND_STRUCT_ELEMENT(round)
    ROUND_STRUCT_ELEMENT(floor)
    ROUND_STRUCT_ELEMENT(ceil)
    ROUND_STRUCT_ELEMENT(trunc)
    ROUND_STRUCT_ELEMENT(cvt)
  };
  T t;

#undef ROUND_STRUCT_ELEMENT

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Save FCSR.
  __ cfc1(a1, FCSR);
  // Disable FPU exceptions.
  __ ctc1(zero_reg, FCSR);
#define RUN_ROUND_TEST(x)                                       \
  __ cfc1(t0, FCSR);                                            \
  __ Sw(t0, MemOperand(a0, offsetof(T, x##_isNaN2008)));        \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, round_up_in)));        \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_up_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, round_down_in)));      \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_down_out)));       \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, neg_round_up_in)));    \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, neg_##x##_up_out)));   \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, neg_round_down_in)));  \
  __ x##_w_d(f0, f0);                                           \
  __ Swc1(f0, MemOperand(a0, offsetof(T, neg_##x##_down_out))); \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err1_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err1_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err2_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err2_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err3_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err3_out)));         \
                                                                \
  __ Ldc1(f0, MemOperand(a0, offsetof(T, err4_in)));            \
  __ ctc1(zero_reg, FCSR);                                      \
  __ x##_w_d(f0, f0);                                           \
  __ cfc1(a2, FCSR);                                            \
  __ Sw(a2, MemOperand(a0, offsetof(T, x##_err4_out)));         \
  __ Swc1(f0, MemOperand(a0, offsetof(T, x##_invalid_result)));

  RUN_ROUND_TEST(round)
  RUN_ROUND_TEST(floor)
  RUN_ROUND_TEST(ceil)
  RUN_ROUND_TEST(trunc)
  RUN_ROUND_TEST(cvt)

  // Restore FCSR.
  __ ctc1(a1, FCSR);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  t.round_up_in = 123.51;
  t.round_down_in = 123.49;
  t.neg_round_up_in = -123.5;
  t.neg_round_down_in = -123.49;
  t.err1_in = 123.51;
  t.err2_in = 1;
  t.err3_in = static_cast<double>(1) + 0xFFFFFFFF;
  t.err4_in = NAN;

  f.Call(&t, 0, 0, 0, 0);

#define GET_FPU_ERR(x) (static_cast<int>(x & kFCSRFlagMask))
#define CHECK_NAN2008(x) (x & kFCSRNaN2008FlagMask)
#define CHECK_ROUND_RESULT(type) \
  CHECK(GET_FPU_ERR(t.type##_err1_out) & kFCSRInexactFlagMask); \
  CHECK_EQ(0, GET_FPU_ERR(t.type##_err2_out)); \
  CHECK(GET_FPU_ERR(t.type##_err3_out) & kFCSRInvalidOpFlagMask); \
  CHECK(GET_FPU_ERR(t.type##_err4_out) & kFCSRInvalidOpFlagMask); \
  if (CHECK_NAN2008(t.type##_isNaN2008) && kArchVariant == kMips64r6) { \
    CHECK_EQ(static_cast<int32_t>(0), t.type##_invalid_result);\
  } else { \
    CHECK_EQ(static_cast<int32_t>(kFPUInvalidResult), t.type##_invalid_result);\
  }

  CHECK_ROUND_RESULT(round);
  CHECK_ROUND_RESULT(floor);
  CHECK_ROUND_RESULT(ceil);
  CHECK_ROUND_RESULT(cvt);
}


TEST(MIPS15) {
  // Test chaining of label usages within instructions (issue 1644).
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  Assembler assm(AssemblerOptions{});

  Label target;
  __ beq(v0, v1, &target);
  __ nop();
  __ bne(v0, v1, &target);
  __ nop();
  __ bind(&target);
  __ nop();
}


// ----- mips64 tests -----------------------------------------------

TEST(MIPS16) {
  // Test 64-bit memory loads and stores.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct T {
    int64_t r1;
    int64_t r2;
    int64_t r3;
    int64_t r4;
    int64_t r5;
    int64_t r6;
    int64_t r7;
    int64_t r8;
    int64_t r9;
    int64_t r10;
    int64_t r11;
    int64_t r12;
    uint32_t ui;
    int32_t si;
  };
  T t;

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

  // Basic 32-bit word load/store, with un-signed data.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a4, MemOperand(a0, offsetof(T, r1)));

  // Check that the data got zero-extended into 64-bit a4.
  __ Sd(a4, MemOperand(a0, offsetof(T, r2)));

  // Basic 32-bit word load/store, with SIGNED data.
  __ Lw(a5, MemOperand(a0, offsetof(T, si)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r3)));

  // Check that the data got sign-extended into 64-bit a4.
  __ Sd(a5, MemOperand(a0, offsetof(T, r4)));

  // 32-bit UNSIGNED word load/store, with SIGNED data.
  __ Lwu(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r5)));

  // Check that the data got zero-extended into 64-bit a4.
  __ Sd(a6, MemOperand(a0, offsetof(T, r6)));

  // lh with positive data.
  __ Lh(a5, MemOperand(a0, offsetof(T, ui)));
  __ Sw(a5, MemOperand(a0, offsetof(T, r7)));

  // lh with negative data.
  __ Lh(a6, MemOperand(a0, offsetof(T, si)));
  __ Sw(a6, MemOperand(a0, offsetof(T, r8)));

  // lhu with negative data.
  __ Lhu(a7, MemOperand(a0, offsetof(T, si)));
  __ Sw(a7, MemOperand(a0, offsetof(T, r9)));

  // Lb with negative data.
  __ Lb(t0, MemOperand(a0, offsetof(T, si)));
  __ Sw(t0, MemOperand(a0, offsetof(T, r10)));

  // sh writes only 1/2 of word.
  __ Lw(a4, MemOperand(a0, offsetof(T, ui)));
  __ Sh(a4, MemOperand(a0, offsetof(T, r11)));
  __ Lw(a4, MemOperand(a0, offsetof(T, si)));
  __ Sh(a4, MemOperand(a0, offsetof(T, r12)));

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);
  t.ui = 0x44332211;
  t.si = 0x99AABBCC;
  t.r1 = 0x5555555555555555;
  t.r2 = 0x5555555555555555;
  t.r3 = 0x5555555555555555;
  t.r4 = 0x5555555555555555;
  t.r5 = 0x5555555555555555;
  t.r6 = 0x5555555555555555;
  t.r7 = 0x5555555555555555;
  t.r8 = 0x5555555555555555;
  t.r9 = 0x5555555555555555;
  t.r10 = 0x5555555555555555;
  t.r11 = 0x5555555555555555;
  t.r12 = 0x5555555555555555;

  f.Call(&t, 0, 0, 0, 0);

  if (kArchEndian == kLittle) {
    // Unsigned data, 32 & 64
    CHECK_EQ(static_cast<int64_t>(0x5555555544332211L), t.r1);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000044332211L), t.r2);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x5555555599AABBCCL), t.r3);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCCL), t.r4);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x5555555599AABBCCL), t.r5);  // lwu, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000099AABBCCL), t.r6);  // sd.

    // lh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x5555555500002211L), t.r7);  // lh, sw.
    CHECK_EQ(static_cast<int64_t>(0x55555555FFFFBBCCL), t.r8);  // lh, sw.

    // lhu with signed data.
    CHECK_EQ(static_cast<int64_t>(0x555555550000BBCCL), t.r9);  // lhu, sw.

    // lb with signed data.
    CHECK_EQ(static_cast<int64_t>(0x55555555FFFFFFCCL), t.r10);  // lb, sw.

    // sh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x5555555555552211L), t.r11);  // lw, sh.
    CHECK_EQ(static_cast<int64_t>(0x555555555555BBCCL), t.r12);  // lw, sh.
  } else {
    // Unsigned data, 32 & 64
    CHECK_EQ(static_cast<int64_t>(0x4433221155555555L), t.r1);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000044332211L), t.r2);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x99AABBCC55555555L), t.r3);  // lw, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFFFF99AABBCCL), t.r4);  // sd.

    // Signed data, 32 & 64.
    CHECK_EQ(static_cast<int64_t>(0x99AABBCC55555555L), t.r5);  // lwu, sw.
    CHECK_EQ(static_cast<int64_t>(0x0000000099AABBCCL), t.r6);  // sd.

    // lh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x0000443355555555L), t.r7);  // lh, sw.
    CHECK_EQ(static_cast<int64_t>(0xFFFF99AA55555555L), t.r8);  // lh, sw.

    // lhu with signed data.
    CHECK_EQ(static_cast<int64_t>(0x000099AA55555555L), t.r9);  // lhu, sw.

    // lb with signed data.
    CHECK_EQ(static_cast<int64_t>(0xFFFFFF9955555555L), t.r10);  // lb, sw.

    // sh with unsigned and signed data.
    CHECK_EQ(static_cast<int64_t>(0x2211555555555555L), t.r11);  // lw, sh.
    CHECK_EQ(static_cast<int64_t>(0xBBCC555555555555L), t.r12);  // lw, sh.
  }
}


// ----------------------mips64r6 specific tests----------------------
TEST(seleqz_selnez) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct Test {
      int a;
      int b;
      int c;
      int d;
      double e;
      double f;
      double g;
      double h;
      float i;
      float j;
      float k;
      float l;
    };

    Test test;
    // Integer part of test.
    __ addiu(t1, zero_reg, 1);                      // t1 = 1
    __ seleqz(t3, t1, zero_reg);                    // t3 = 1
    __ Sw(t3, MemOperand(a0, offsetof(Test, a)));   // a = 1
    __ seleqz(t2, t1, t1);                          // t2 = 0
    __ Sw(t2, MemOperand(a0, offsetof(Test, b)));   // b = 0
    __ selnez(t3, t1, zero_reg);                    // t3 = 1;
    __ Sw(t3, MemOperand(a0, offsetof(Test, c)));   // c = 0
    __ selnez(t3, t1, t1);                          // t3 = 1
    __ Sw(t3, MemOperand(a0, offsetof(Test, d)));   // d = 1
    // Floating point part of test.
    __ Ldc1(f0, MemOperand(a0, offsetof(Test, e)));   // src
    __ Ldc1(f2, MemOperand(a0, offsetof(Test, f)));   // test
    __ Lwc1(f8, MemOperand(a0, offsetof(Test, i)));   // src
    __ Lwc1(f10, MemOperand(a0, offsetof(Test, j)));  // test
    __ seleqz_d(f4, f0, f2);
    __ selnez_d(f6, f0, f2);
    __ seleqz_s(f12, f8, f10);
    __ selnez_s(f14, f8, f10);
    __ Sdc1(f4, MemOperand(a0, offsetof(Test, g)));   // src
    __ Sdc1(f6, MemOperand(a0, offsetof(Test, h)));   // src
    __ Swc1(f12, MemOperand(a0, offsetof(Test, k)));  // src
    __ Swc1(f14, MemOperand(a0, offsetof(Test, l)));  // src
    __ jr(ra);
    __ nop();
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    f.Call(&test, 0, 0, 0, 0);

    CHECK_EQ(1, test.a);
    CHECK_EQ(0, test.b);
    CHECK_EQ(0, test.c);
    CHECK_EQ(1, test.d);

    const int test_size = 3;
    const int input_size = 5;

    double inputs_D[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double outputs_D[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double tests_D[test_size*2] = {2.8, 2.9, -2.8, -2.9,
      18446744073709551616.0, 18446744073709555712.0};
    float inputs_S[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float outputs_S[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float tests_S[test_size*2] = {2.9, 2.8, -2.9, -2.8,
      18446744073709551616.0, 18446746272732807168.0};
    for (int j = 0; j < test_size; j += 2) {
      for (int i=0; i < input_size; i++) {
        test.e = inputs_D[i];
        test.f = tests_D[j];
        test.i = inputs_S[i];
        test.j = tests_S[j];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(outputs_D[i], test.g);
        CHECK_EQ(0, test.h);
        CHECK_EQ(outputs_S[i], test.k);
        CHECK_EQ(0, test.l);

        test.f = tests_D[j+1];
        test.j = tests_S[j+1];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(0, test.g);
        CHECK_EQ(outputs_D[i], test.h);
        CHECK_EQ(0, test.k);
        CHECK_EQ(outputs_S[i], test.l);
      }
    }
  }
}



TEST(min_max) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      double a;
      double b;
      double c;
      double d;
      float e;
      float f;
      float g;
      float h;
    };

    TestFloat test;
    const double dnan = std::numeric_limits<double>::quiet_NaN();
    const double dinf = std::numeric_limits<double>::infinity();
    const double dminf = -std::numeric_limits<double>::infinity();
    const float fnan = std::numeric_limits<float>::quiet_NaN();
    const float finf = std::numeric_limits<float>::infinity();
    const float fminf = std::numeric_limits<float>::infinity();
    const int kTableLength = 13;
    double inputsa[kTableLength] = {2.0,  3.0,  dnan, 3.0,   -0.0, 0.0, dinf,
                                    dnan, 42.0, dinf, dminf, dinf, dnan};
    double inputsb[kTableLength] = {3.0,  2.0,  3.0,  dnan, 0.0,   -0.0, dnan,
                                    dinf, dinf, 42.0, dinf, dminf, dnan};
    double outputsdmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                        -0.0,  dinf,  dinf, 42.0, 42.0,
                                        dminf, dminf, dnan};
    double outputsdmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, dinf,
                                        dinf, dinf, dinf, dinf, dinf, dnan};

    float inputse[kTableLength] = {2.0,  3.0,  fnan, 3.0,   -0.0, 0.0, finf,
                                   fnan, 42.0, finf, fminf, finf, fnan};
    float inputsf[kTableLength] = {3.0,  2.0,  3.0,  fnan, 0.0,   -0.0, fnan,
                                   finf, finf, 42.0, finf, fminf, fnan};
    float outputsfmin[kTableLength] = {2.0,   2.0,   3.0,  3.0,  -0.0,
                                       -0.0,  finf,  finf, 42.0, 42.0,
                                       fminf, fminf, fnan};
    float outputsfmax[kTableLength] = {3.0,  3.0,  3.0,  3.0,  0.0,  0.0, finf,
                                       finf, finf, finf, finf, finf, fnan};

    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Ldc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ Lwc1(f2, MemOperand(a0, offsetof(TestFloat, e)));
    __ Lwc1(f6, MemOperand(a0, offsetof(TestFloat, f)));
    __ min_d(f10, f4, f8);
    __ max_d(f12, f4, f8);
    __ min_s(f14, f2, f6);
    __ max_s(f16, f2, f6);
    __ Sdc1(f10, MemOperand(a0, offsetof(TestFloat, c)));
    __ Sdc1(f12, MemOperand(a0, offsetof(TestFloat, d)));
    __ Swc1(f14, MemOperand(a0, offsetof(TestFloat, g)));
    __ Swc1(f16, MemOperand(a0, offsetof(TestFloat, h)));
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);
    for (int i = 4; i < kTableLength; i++) {
      test.a = inputsa[i];
      test.b = inputsb[i];
      test.e = inputse[i];
      test.f = inputsf[i];

      f.Call(&test, 0, 0, 0, 0);

      CHECK_EQ(0, memcmp(&test.c, &outputsdmin[i], sizeof(test.c)));
      CHECK_EQ(0, memcmp(&test.d, &outputsdmax[i], sizeof(test.d)));
      CHECK_EQ(0, memcmp(&test.g, &outputsfmin[i], sizeof(test.g)));
      CHECK_EQ(0, memcmp(&test.h, &outputsfmax[i], sizeof(test.h)));
    }
  }
}


TEST(rint_d)  {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 30;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      double a;
      double b;
      int fcsr;
    };

    TestFloat test;
    double inputs[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E+308, 6.27463370218383111104242366943E-307,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RN[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RZ[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RP[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    double outputs_RM[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E147,
      1.7976931348623157E308, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    int fcsr_inputs[4] =
      {kRoundToNearest, kRoundToZero, kRoundToPlusInf, kRoundToMinusInf};
    double* outputs[4] = {outputs_RN, outputs_RZ, outputs_RP, outputs_RM};
    __ Ldc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Lw(t0, MemOperand(a0, offsetof(TestFloat, fcsr)));
    __ ctc1(t0, FCSR);
    __ rint_d(f8, f4);
    __ Sdc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    for (int j = 0; j < 4; j++) {
      test.fcsr = fcsr_inputs[j];
      for (int i = 0; i < kTableLength; i++) {
        test.a = inputs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.b, outputs[j][i]);
      }
    }
  }
}


TEST(sel) {
  if (kArchVariant == kMips64r6) {
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct Test {
      double dd;
      double ds;
      double dt;
      float fd;
      float fs;
      float ft;
    };

    Test test;
    __ Ldc1(f0, MemOperand(a0, offsetof(Test, dd)));   // test
    __ Ldc1(f2, MemOperand(a0, offsetof(Test, ds)));   // src1
    __ Ldc1(f4, MemOperand(a0, offsetof(Test, dt)));   // src2
    __ Lwc1(f6, MemOperand(a0, offsetof(Test, fd)));   // test
    __ Lwc1(f8, MemOperand(a0, offsetof(Test, fs)));   // src1
    __ Lwc1(f10, MemOperand(a0, offsetof(Test, ft)));  // src2
    __ sel_d(f0, f2, f4);
    __ sel_s(f6, f8, f10);
    __ Sdc1(f0, MemOperand(a0, offsetof(Test, dd)));
    __ Swc1(f6, MemOperand(a0, offsetof(Test, fd)));
    __ jr(ra);
    __ nop();
    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    const int test_size = 3;
    const int input_size = 5;

    double inputs_dt[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    double inputs_ds[input_size] = {0.1, 69.88, -91.325,
      18446744073709551625.0, -18446744073709551625.0};
    float inputs_ft[input_size] = {0.0, 65.2, -70.32,
      18446744073709551621.0, -18446744073709551621.0};
    float inputs_fs[input_size] = {0.1, 69.88, -91.325,
      18446744073709551625.0, -18446744073709551625.0};
    double tests_D[test_size*2] = {2.8, 2.9, -2.8, -2.9,
      18446744073709551616.0, 18446744073709555712.0};
    float tests_S[test_size*2] = {2.9, 2.8, -2.9, -2.8,
      18446744073709551616.0, 18446746272732807168.0};
    for (int j = 0; j < test_size; j += 2) {
      for (int i=0; i < input_size; i++) {
        test.dt = inputs_dt[i];
        test.dd = tests_D[j];
        test.ds = inputs_ds[i];
        test.ft = inputs_ft[i];
        test.fd = tests_S[j];
        test.fs = inputs_fs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dd, inputs_ds[i]);
        CHECK_EQ(test.fd, inputs_fs[i]);

        test.dd = tests_D[j+1];
        test.fd = tests_S[j+1];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.dd, inputs_dt[i]);
        CHECK_EQ(test.fd, inputs_ft[i]);
      }
    }
  }
}


TEST(rint_s)  {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 30;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);

    struct TestFloat {
      float a;
      float b;
      int fcsr;
    };

    TestFloat test;
    float inputs[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E+38, 6.27463370218383111104242366943E-37,
      309485009821345068724781056.89,
      2.1, 2.6, 2.5, 3.1, 3.6, 3.5,
      -2.1, -2.6, -2.5, -3.1, -3.6, -3.5,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RN[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 3.0, 2.0, 3.0, 4.0, 4.0,
      -2.0, -3.0, -2.0, -3.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RZ[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RP[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 1,
      309485009821345068724781057.0,
      3.0, 3.0, 3.0, 4.0, 4.0, 4.0,
      -2.0, -2.0, -2.0, -3.0, -3.0, -3.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    float outputs_RM[kTableLength] = {18446744073709551617.0,
      4503599627370496.0, -4503599627370496.0,
      1.26782468584154733584017312973E30, 1.44860108245951772690707170478E37,
      1.7976931348623157E38, 0,
      309485009821345068724781057.0,
      2.0, 2.0, 2.0, 3.0, 3.0, 3.0,
      -3.0, -3.0, -3.0, -4.0, -4.0, -4.0,
      37778931862957161709568.0, 37778931862957161709569.0,
      37778931862957161709580.0, 37778931862957161709581.0,
      37778931862957161709582.0, 37778931862957161709583.0,
      37778931862957161709584.0, 37778931862957161709585.0,
      37778931862957161709586.0, 37778931862957161709587.0};
    int fcsr_inputs[4] =
      {kRoundToNearest, kRoundToZero, kRoundToPlusInf, kRoundToMinusInf};
    float* outputs[4] = {outputs_RN, outputs_RZ, outputs_RP, outputs_RM};
    __ Lwc1(f4, MemOperand(a0, offsetof(TestFloat, a)));
    __ Lw(t0, MemOperand(a0, offsetof(TestFloat, fcsr)));
    __ cfc1(t1, FCSR);
    __ ctc1(t0, FCSR);
    __ rint_s(f8, f4);
    __ Swc1(f8, MemOperand(a0, offsetof(TestFloat, b)));
    __ ctc1(t1, FCSR);
    __ jr(ra);
    __ nop();

    CodeDesc desc;
    assm.GetCode(isolate, &desc);
    Handle<Code> code =
        Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
    auto f = GeneratedCode<F3>::FromCode(isolate, *code);

    for (int j = 0; j < 4; j++) {
      test.fcsr = fcsr_inputs[j];
      for (int i = 0; i < kTableLength; i++) {
        test.a = inputs[i];
        f.Call(&test, 0, 0, 0, 0);
        CHECK_EQ(test.b, outputs[j][i]);
      }
    }
  }
}


TEST(mina_maxa) {
  if (kArchVariant == kMips64r6) {
    const int kTableLength = 23;
    CcTest::InitializeVM();
    Isolate* isolate = CcTest::i_isolate();
    HandleScope scope(isolate);
    MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
    const double dnan = std::numeric_limits<double>::quiet_NaN();
    const double dinf = std::numeric_limits<double>::infinity();
    const double dminf = -std::numeric_limits<double>::infinity();
    const float fnan = std::numeric_limits<float>::quiet_NaN();
    const float finf = std::numeric_limits<float>::infinity();
    const float fminf = std::numeric_limits<float>::infinity();

    struct TestFloat {
      double a;
      double b;
      double resd;
      double resd1;
      float c;
      float d;
      float resf;
      float resf1;
    };

    TestFloat test;
    double inputsa[kTableLength] = {
        5.3,  4.8, 6.1,  9.8, 9.8,  9.8,  -10.0, -8.9, -9.8,  -10.0, -8.9, -9.8,
        dnan, 3.0, -0.0, 0.0, dinf, dnan, 42.0,  dinf, dminf, dinf,  dnan};
    doub
"""


```