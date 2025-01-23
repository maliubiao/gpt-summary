Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the summary.

1. **Understanding the Context:** The prompt clearly states this is part of a larger file (`v8/test/cctest/test-assembler-arm64.cc`) within the V8 JavaScript engine's testing framework. The file name suggests it tests the ARM64 assembler. The presence of `TEST()` macros reinforces that these are unit tests. The prompt also gives important hints about `.tq` files (Torque) and the relation to JavaScript.

2. **Initial Scan for Keywords:**  Quickly scan the code for significant keywords and patterns:
    * `TEST(...)`:  Indicates individual test cases. Note the descriptive names like `ual`, `cas`, `casb`, `cash`, `casp`, `atomic_memory_...`, `process_nan_...`.
    * `INIT_V8()`, `SETUP()`, `START()`, `END()`, `RUN()`:  These are likely part of the testing infrastructure, setting up the environment, starting and running the generated assembly code.
    * `__ Mov(...)`:  Likely an assembler instruction to move data into registers or memory.
    * `__ Cas(...)`, `__ Casb(...)`, etc.: These look like Compare-and-Swap instructions with different data sizes and ordering semantics (acquire/release). The 'p' suffix likely means "pair."
    * `CHECK_EQUAL_...`: Assertion macros to verify the expected results. The suffixes like `_64` and `_FP64` indicate the data types being checked.
    * `SETUP_FEATURE(LSE)`:  Indicates that some tests might depend on specific ARM Large System Extension (LSE) features.
    * `reinterpret_cast<uintptr_t>(&...)`:  Taking the address of variables.
    * `alignas(...)`:  Specifying memory alignment.
    * `AtomicMemory...Helper`:  Suggests helper functions for testing atomic memory operations.
    * `IsSignallingNaN(...)`, `IsQuietNaN(...)`: Functions related to checking NaN (Not-a-Number) values in floating-point operations.
    * `base::bit_cast<...>(...)`:  Reinterpreting the bit pattern of data.
    * `std::isnan(...)`: Standard C++ function for checking if a number is NaN.

3. **Categorizing the Tests:**  Group the tests by their names to identify common functionalities:
    * `ual`:  Likely related to Unaligned Load/Store operations. The numbers in the test names (`64_1`, `64_2`, etc.) might relate to different scenarios or data patterns.
    * `cas`, `casb`, `cash`, `casp`:  These clearly test different variations of Compare-and-Swap operations (word, byte, half-word, pair). The `_x` suffix might indicate tests with exclusive access or different register usage.
    * `atomic_memory_...`:  Focuses on testing various atomic memory operations like add, clear, eor, set, min, max, and swap. The 'w' and 'x' suffixes in the helper function names likely denote word-sized and register-sized operations.
    * `process_nan_...`:  Dedicated to testing how NaN values are handled in floating-point operations.

4. **Analyzing Individual Test Logic (High-Level):**  For a few representative tests, try to understand the basic flow:
    * **`ual`:**  Load specific values into memory locations and then use `UAL_64` (presumably an assembler instruction being tested) to load from these potentially unaligned locations. The `CHECK_EQUAL_64` assertions verify that the correct values are loaded.
    * **`cas`:** Set up memory locations with initial values. Load values into registers. Execute `Cas` (or its variants), which will attempt to atomically update the memory location *only if* the current value matches the expected value. The assertions check both the register values (did the swap happen?) and the memory values.
    * **`atomic_memory_add`:** Initialize memory with a value, then use atomic add operations to modify it. The helper functions make the test setup more structured.
    * **`process_nan_double`:**  Load NaN values into floating-point registers. Perform various floating-point operations. Assert that the resulting values are the expected NaN representations after V8's NaN processing.

5. **Connecting to JavaScript (If Applicable):** Consider how these low-level assembler tests relate to JavaScript functionality. Atomic operations are crucial for implementing concurrent features and shared memory access. NaN handling is fundamental to JavaScript's number type and its behavior in mathematical operations. While the direct assembly code isn't exposed to JS developers, its correctness ensures the reliability of JS features.

6. **Inferring Functionality (Based on Names and Operations):**  Even without deep knowledge of the V8 codebase, the names of the tests and the assembly instructions used provide strong clues about the functionality being tested. For example, "cas" clearly points to Compare-and-Swap. "atomic_memory_add" suggests testing the atomicity and correctness of addition operations on memory.

7. **Addressing Specific Prompt Questions:** Now, go through each part of the prompt systematically:
    * **Functionality:** Summarize the observed behavior of each group of tests.
    * **`.tq` files:** State that this is a `.cc` file and thus C++, not Torque.
    * **JavaScript relation:** Explain the connection to JavaScript concepts like atomics and NaN handling. Provide concise JS examples demonstrating these concepts.
    * **Code logic reasoning (input/output):**  For a simple test like `ual`, provide a concrete example of input memory values and the expected output register values.
    * **Common programming errors:** Think about common mistakes related to atomics (race conditions, incorrect ordering) and NaN handling (unexpected results in calculations).
    * **Overall function (for this part):**  Synthesize the purpose of this specific section of the code.

8. **Structuring the Output:** Organize the information logically, using headings and bullet points for clarity. Start with a general overview, then delve into the specifics of each test group. Address each part of the prompt clearly.

9. **Review and Refine:** Read through the generated summary to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas where the explanation could be improved. For instance, initially, I might just say "tests compare and swap," but refining it to explain the different sizes and ordering is more helpful. Also, emphasizing that these are *unit tests* for the *assembler* is crucial.
好的，让我们来分析一下这段 C++ 代码的功能。

**文件功能概要:**

`v8/test/cctest/test-assembler-arm64.cc` 是 V8 JavaScript 引擎的一部分，它包含了针对 ARM64 架构汇编器的单元测试。这些测试旨在验证 ARM64 汇编器生成的指令的正确性，包括：

* **非对齐内存访问 (Unaligned Access):** 测试在内存地址不是数据类型大小的倍数时，加载和存储操作是否正确执行。
* **原子操作 (Atomic Operations):**  测试各种原子操作指令，例如 Compare-and-Swap (CAS) 及其变体，以及其他原子内存操作 (例如 Add, Clear, Eor, Set, Min, Max, Swap)。这些操作用于在多线程环境中安全地访问共享内存。
* **浮点数 NaN (Not-a-Number) 处理:** 测试汇编器在处理 NaN 值时的行为是否符合 IEEE 754 标准，包括 NaN 的传播和规范化。

**关于文件类型:**

代码以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。Torque 是一种 V8 特定的语言，用于定义内置函数的实现。

**与 JavaScript 的关系:**

这段代码直接测试的是底层的汇编器，但这与 JavaScript 的功能密切相关。

* **原子操作:** JavaScript 提供了 `Atomics` 对象，允许在共享内存上执行原子操作。这段 C++ 代码中的测试直接验证了这些 `Atomics` 操作在 ARM64 架构上的底层实现是否正确。例如，`Atomics.compareExchange()` 的底层实现会用到类似 `cas` 指令。
* **浮点数 NaN:** JavaScript 中的数字类型是 IEEE 754 双精度浮点数。这段代码测试了汇编器在处理 NaN 值时的正确性，这直接影响了 JavaScript 中涉及到 NaN 的运算结果。

**JavaScript 示例:**

```javascript
// 原子操作示例
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);
Atomics.store(view, 0, 10); // 初始值

const oldValue = 10;
const newValue = 20;
const result = Atomics.compareExchange(view, 0, oldValue, newValue);

console.log(result); // 如果 view[0] 的值是 oldValue (10)，则返回 oldValue (10)，并将 view[0] 更新为 newValue (20)
console.log(Atomics.load(view, 0)); // 输出更新后的值 (可能是 20，也可能是 10，取决于 compareExchange 是否成功)

// NaN 示例
const nanValue = NaN;
const result1 = nanValue + 10;
const result2 = nanValue > 5;

console.log(result1); // NaN
console.log(result2); // false
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST(ual_64_1)` 为例：

**假设输入:**

* 内存地址 `data1` 存储 64 位值 `0x0123456789abcdef`。
* `x21` 寄存器指向 `data1` 的地址。

**汇编指令:**

```assembly
__ Ldr(x1, MemOperand(x21));      // 加载 data1 的值到 x1
__ Ldr(x2, MemOperand(x21, 1));   // 从 data1 地址偏移 1 字节处加载到 x2
__ Ldr(x3, MemOperand(x21, 2));   // 从 data1 地址偏移 2 字节处加载到 x3
// ...以此类推
```

**预期输出:**

由于是非对齐加载，每个 `Ldr` 指令会从指定的偏移地址开始读取 8 个字节 (64 位)。

* `x1` 应该等于 `0x0123456789abcdef` (完整的值)。
* `x2` 应该等于 `0x??0123456789abcde` (取决于字节序，这里假设小端序，低位在前)。
* `x3` 应该等于 `0x????0123456789abcd`。
* ...等等。

`CHECK_EQUAL_64` 宏会验证实际加载的值是否与预期值相等。

**用户常见的编程错误:**

* **原子操作使用不当导致的竞态条件 (Race Condition):**  在多线程环境中，如果没有正确使用原子操作来保护共享资源，可能会导致数据损坏或意外行为。

   ```c++
   // 错误示例 (非原子操作)
   uint32_t counter = 0;

   void increment() {
     // 多个线程可能同时执行这段代码
     uint32_t temp = counter;
     temp++;
     counter = temp; // 这里可能发生数据竞争
   }
   ```

   正确的做法是使用原子操作：

   ```c++
   std::atomic<uint32_t> counter(0);

   void increment() {
     counter++; // 原子自增操作
   }
   ```

* **浮点数 NaN 的比较和运算错误:**  开发者可能错误地使用 `==` 来比较 NaN 值，或者没有考虑到 NaN 在算术运算中的传播特性。

   ```javascript
   const nanValue = NaN;
   console.log(nanValue == NaN);   // false (NaN 不等于自身)
   console.log(isNaN(nanValue));   // true (应该使用 isNaN() 来检查)
   console.log(nanValue + 10 > 5); // false (任何与 NaN 的比较结果都是 false)
   ```

**归纳功能 (第 14 部分，共 15 部分):**

作为第 14 部分，这段代码主要集中在测试 ARM64 汇编器的以下功能：

* **各种 Compare-and-Swap (CAS) 指令及其变体 (带 acquire/release 语义):**  包括对不同数据大小 (word, byte, half-word, pair) 的测试。
* **更广泛的原子内存操作:** 测试 `add`, `clr`, `eor`, `set`, `smax`, `smin`, `umax`, `umin`, `swp` 等原子操作指令。
* **浮点数 NaN 值的处理:**  测试在浮点运算中，特别是涉及到 `fmov`, `fabs`, `fneg`, `fsqrt`, `frinta`, `frintn`, `frintz`, `fadd`, `fsub`, `fmul`, `fdiv`, `fmax`, `fmin` 等指令时，如何正确处理和传播 NaN 值。

总的来说，这部分测试深入验证了 ARM64 汇编器在处理并发场景下的内存访问和特殊浮点数值时的正确性和可靠性，这对于 V8 引擎在 ARM64 架构上的稳定运行至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
UAL_64(0x01234567ffffffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0xffffffff89abcdef, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0x01234567ffffffff, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffffffff89abcdef, data8);
  }
}

TEST(cas_casa_casl_casal_x) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3));
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4));
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5));
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6));
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7));
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8));

  __ Mov(x0, 0xffffffffffffffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0x0123456789abcdef);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x0123456789abcdef);

  __ Cas(x1, x0, MemOperand(x21));
  __ Cas(x2, x0, MemOperand(x22));
  __ Casa(x3, x0, MemOperand(x23));
  __ Casa(x4, x0, MemOperand(x24));
  __ Casl(x5, x0, MemOperand(x25));
  __ Casl(x6, x0, MemOperand(x26));
  __ Casal(x7, x0, MemOperand(x27));
  __ Casal(x8, x0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x0123456789abcdef, x1);
    CHECK_EQUAL_64(0x0123456789abcdef, x2);
    CHECK_EQUAL_64(0x0123456789abcdef, x3);
    CHECK_EQUAL_64(0x0123456789abcdef, x4);
    CHECK_EQUAL_64(0x0123456789abcdef, x5);
    CHECK_EQUAL_64(0x0123456789abcdef, x6);
    CHECK_EQUAL_64(0x0123456789abcdef, x7);
    CHECK_EQUAL_64(0x0123456789abcdef, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQUAL_64(0xffffffffffffffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0xffffffffffffffff, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0xffffffffffffffff, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffffffffffffffff, data8);
  }
}

TEST(casb_casab_caslb_casalb) {
  uint32_t data1 = 0x01234567;
  uint32_t data2 = 0x01234567;
  uint32_t data3 = 0x01234567;
  uint32_t data4 = 0x01234567;
  uint32_t data5 = 0x01234567;
  uint32_t data6 = 0x01234567;
  uint32_t data7 = 0x01234567;
  uint32_t data8 = 0x01234567;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 1);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 1);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 2);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 2);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 3);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 3);

  __ Mov(x0, 0xff);

  __ Mov(x1, 0x76543210);
  __ Mov(x2, 0x01234567);
  __ Mov(x3, 0x76543210);
  __ Mov(x4, 0x67012345);
  __ Mov(x5, 0x76543210);
  __ Mov(x6, 0x45670123);
  __ Mov(x7, 0x76543210);
  __ Mov(x8, 0x23456701);

  __ Casb(w1, w0, MemOperand(x21));
  __ Casb(w2, w0, MemOperand(x22));
  __ Casab(w3, w0, MemOperand(x23));
  __ Casab(w4, w0, MemOperand(x24));
  __ Caslb(w5, w0, MemOperand(x25));
  __ Caslb(w6, w0, MemOperand(x26));
  __ Casalb(w7, w0, MemOperand(x27));
  __ Casalb(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x00000067, x1);
    CHECK_EQUAL_64(0x00000067, x2);
    CHECK_EQUAL_64(0x00000045, x3);
    CHECK_EQUAL_64(0x00000045, x4);
    CHECK_EQUAL_64(0x00000023, x5);
    CHECK_EQUAL_64(0x00000023, x6);
    CHECK_EQUAL_64(0x00000001, x7);
    CHECK_EQUAL_64(0x00000001, x8);

    CHECK_EQUAL_64(0x01234567, data1);
    CHECK_EQUAL_64(0x012345ff, data2);
    CHECK_EQUAL_64(0x01234567, data3);
    CHECK_EQUAL_64(0x0123ff67, data4);
    CHECK_EQUAL_64(0x01234567, data5);
    CHECK_EQUAL_64(0x01ff4567, data6);
    CHECK_EQUAL_64(0x01234567, data7);
    CHECK_EQUAL_64(0xff234567, data8);
  }
}

TEST(cash_casah_caslh_casalh) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 2);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 2);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 4);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 4);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 6);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 6);

  __ Mov(x0, 0xffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0xcdef0123456789ab);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x89abcdef01234567);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x456789abcdef0123);

  __ Cash(w1, w0, MemOperand(x21));
  __ Cash(w2, w0, MemOperand(x22));
  __ Casah(w3, w0, MemOperand(x23));
  __ Casah(w4, w0, MemOperand(x24));
  __ Caslh(w5, w0, MemOperand(x25));
  __ Caslh(w6, w0, MemOperand(x26));
  __ Casalh(w7, w0, MemOperand(x27));
  __ Casalh(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x0000cdef, x1);
    CHECK_EQUAL_64(0x0000cdef, x2);
    CHECK_EQUAL_64(0x000089ab, x3);
    CHECK_EQUAL_64(0x000089ab, x4);
    CHECK_EQUAL_64(0x00004567, x5);
    CHECK_EQUAL_64(0x00004567, x6);
    CHECK_EQUAL_64(0x00000123, x7);
    CHECK_EQUAL_64(0x00000123, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQUAL_64(0x0123456789abffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0x01234567ffffcdef, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0x0123ffff89abcdef, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffff456789abcdef, data8);
  }
}

TEST(casp_caspa_caspl_caspal_w) {
  uint64_t data1[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data2[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data3[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data4[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data5[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data6[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data7[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data8[] = {0x7766554433221100, 0xffeeddccbbaa9988};

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3) + 8);
  __ Mov(x24, reinterpret_cast<uintptr_t>(data4) + 8);
  __ Mov(x25, reinterpret_cast<uintptr_t>(data5) + 8);
  __ Mov(x26, reinterpret_cast<uintptr_t>(data6) + 8);
  __ Mov(x27, reinterpret_cast<uintptr_t>(data7) + 0);
  __ Mov(x28, reinterpret_cast<uintptr_t>(data8) + 0);

  __ Mov(x0, 0xfff00fff);
  __ Mov(x1, 0xfff11fff);

  __ Mov(x2, 0x77665544);
  __ Mov(x3, 0x33221100);
  __ Mov(x4, 0x33221100);
  __ Mov(x5, 0x77665544);

  __ Mov(x6, 0xffeeddcc);
  __ Mov(x7, 0xbbaa9988);
  __ Mov(x8, 0xbbaa9988);
  __ Mov(x9, 0xffeeddcc);

  __ Mov(x10, 0xffeeddcc);
  __ Mov(x11, 0xbbaa9988);
  __ Mov(x12, 0xbbaa9988);
  __ Mov(x13, 0xffeeddcc);

  __ Mov(x14, 0x77665544);
  __ Mov(x15, 0x33221100);
  __ Mov(x16, 0x33221100);
  __ Mov(x17, 0x77665544);

  __ Casp(w2, w3, w0, w1, MemOperand(x21));
  __ Casp(w4, w5, w0, w1, MemOperand(x22));
  __ Caspa(w6, w7, w0, w1, MemOperand(x23));
  __ Caspa(w8, w9, w0, w1, MemOperand(x24));
  __ Caspl(w10, w11, w0, w1, MemOperand(x25));
  __ Caspl(w12, w13, w0, w1, MemOperand(x26));
  __ Caspal(w14, w15, w0, w1, MemOperand(x27));
  __ Caspal(w16, w17, w0, w1, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x33221100, x2);
    CHECK_EQUAL_64(0x77665544, x3);
    CHECK_EQUAL_64(0x33221100, x4);
    CHECK_EQUAL_64(0x77665544, x5);
    CHECK_EQUAL_64(0xbbaa9988, x6);
    CHECK_EQUAL_64(0xffeeddcc, x7);
    CHECK_EQUAL_64(0xbbaa9988, x8);
    CHECK_EQUAL_64(0xffeeddcc, x9);
    CHECK_EQUAL_64(0xbbaa9988, x10);
    CHECK_EQUAL_64(0xffeeddcc, x11);
    CHECK_EQUAL_64(0xbbaa9988, x12);
    CHECK_EQUAL_64(0xffeeddcc, x13);
    CHECK_EQUAL_64(0x33221100, x14);
    CHECK_EQUAL_64(0x77665544, x15);
    CHECK_EQUAL_64(0x33221100, x16);
    CHECK_EQUAL_64(0x77665544, x17);

    CHECK_EQUAL_64(0x7766554433221100, data1[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data1[1]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data2[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data2[1]);
    CHECK_EQUAL_64(0x7766554433221100, data3[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data3[1]);
    CHECK_EQUAL_64(0x7766554433221100, data4[0]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data4[1]);
    CHECK_EQUAL_64(0x7766554433221100, data5[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data5[1]);
    CHECK_EQUAL_64(0x7766554433221100, data6[0]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data6[1]);
    CHECK_EQUAL_64(0x7766554433221100, data7[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data7[1]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data8[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data8[1]);
  }
}

TEST(casp_caspa_caspl_caspal_x) {
  alignas(kXRegSize * 2)
      uint64_t data1[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data2[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data3[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data4[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data5[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data6[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data7[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data8[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3) + 16);
  __ Mov(x24, reinterpret_cast<uintptr_t>(data4) + 16);
  __ Mov(x25, reinterpret_cast<uintptr_t>(data5) + 16);
  __ Mov(x26, reinterpret_cast<uintptr_t>(data6) + 16);
  __ Mov(x27, reinterpret_cast<uintptr_t>(data7) + 0);
  __ Mov(x28, reinterpret_cast<uintptr_t>(data8) + 0);

  __ Mov(x0, 0xfffffff00fffffff);
  __ Mov(x1, 0xfffffff11fffffff);

  __ Mov(x2, 0xffeeddccbbaa9988);
  __ Mov(x3, 0x7766554433221100);
  __ Mov(x4, 0x7766554433221100);
  __ Mov(x5, 0xffeeddccbbaa9988);

  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0xfedcba9876543210);
  __ Mov(x9, 0x0123456789abcdef);

  __ Mov(x10, 0x0123456789abcdef);
  __ Mov(x11, 0xfedcba9876543210);
  __ Mov(x12, 0xfedcba9876543210);
  __ Mov(x13, 0x0123456789abcdef);

  __ Mov(x14, 0xffeeddccbbaa9988);
  __ Mov(x15, 0x7766554433221100);
  __ Mov(x16, 0x7766554433221100);
  __ Mov(x17, 0xffeeddccbbaa9988);

  __ Casp(x2, x3, x0, x1, MemOperand(x21));
  __ Casp(x4, x5, x0, x1, MemOperand(x22));
  __ Caspa(x6, x7, x0, x1, MemOperand(x23));
  __ Caspa(x8, x9, x0, x1, MemOperand(x24));
  __ Caspl(x10, x11, x0, x1, MemOperand(x25));
  __ Caspl(x12, x13, x0, x1, MemOperand(x26));
  __ Caspal(x14, x15, x0, x1, MemOperand(x27));
  __ Caspal(x16, x17, x0, x1, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x7766554433221100, x2);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x3);
    CHECK_EQUAL_64(0x7766554433221100, x4);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x5);

    CHECK_EQUAL_64(0xfedcba9876543210, x6);
    CHECK_EQUAL_64(0x0123456789abcdef, x7);
    CHECK_EQUAL_64(0xfedcba9876543210, x8);
    CHECK_EQUAL_64(0x0123456789abcdef, x9);

    CHECK_EQUAL_64(0xfedcba9876543210, x10);
    CHECK_EQUAL_64(0x0123456789abcdef, x11);
    CHECK_EQUAL_64(0xfedcba9876543210, x12);
    CHECK_EQUAL_64(0x0123456789abcdef, x13);

    CHECK_EQUAL_64(0x7766554433221100, x14);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x15);
    CHECK_EQUAL_64(0x7766554433221100, x16);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x17);

    CHECK_EQUAL_64(0x7766554433221100, data1[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data1[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data1[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data1[3]);

    CHECK_EQUAL_64(0xfffffff00fffffff, data2[0]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data2[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data2[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data2[3]);

    CHECK_EQUAL_64(0x7766554433221100, data3[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data3[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data3[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data3[3]);

    CHECK_EQUAL_64(0x7766554433221100, data4[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data4[1]);
    CHECK_EQUAL_64(0xfffffff00fffffff, data4[2]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data4[3]);

    CHECK_EQUAL_64(0x7766554433221100, data5[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data5[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data5[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data5[3]);

    CHECK_EQUAL_64(0x7766554433221100, data6[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data6[1]);
    CHECK_EQUAL_64(0xfffffff00fffffff, data6[2]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data6[3]);

    CHECK_EQUAL_64(0x7766554433221100, data7[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data7[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data7[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data7[3]);

    CHECK_EQUAL_64(0xfffffff00fffffff, data8[0]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data8[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data8[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data8[3]);
  }
}

typedef void (MacroAssembler::*AtomicMemoryLoadSignature)(
    const Register& rs, const Register& rt, const MemOperand& src);
typedef void (MacroAssembler::*AtomicMemoryStoreSignature)(
    const Register& rs, const MemOperand& src);

static void AtomicMemoryWHelper(AtomicMemoryLoadSignature* load_funcs,
                                AtomicMemoryStoreSignature* store_funcs,
                                uint64_t arg1, uint64_t arg2, uint64_t expected,
                                uint64_t result_mask) {
  alignas(kXRegSize * 2) uint64_t data0[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data1[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data2[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data3[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data4[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data5[] = {arg2, 0};

  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x20, reinterpret_cast<uintptr_t>(data0));
  __ Mov(x21, reinterpret_cast<uintptr_t>(data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3));

  __ Mov(x0, arg1);
  __ Mov(x1, arg1);
  __ Mov(x2, arg1);
  __ Mov(x3, arg1);

  (masm.*(load_funcs[0]))(w0, w10, MemOperand(x20));
  (masm.*(load_funcs[1]))(w1, w11, MemOperand(x21));
  (masm.*(load_funcs[2]))(w2, w12, MemOperand(x22));
  (masm.*(load_funcs[3]))(w3, w13, MemOperand(x23));

  if (store_funcs != NULL) {
    __ Mov(x24, reinterpret_cast<uintptr_t>(data4));
    __ Mov(x25, reinterpret_cast<uintptr_t>(data5));
    __ Mov(x4, arg1);
    __ Mov(x5, arg1);

    (masm.*(store_funcs[0]))(w4, MemOperand(x24));
    (masm.*(store_funcs[1]))(w5, MemOperand(x25));
  }

  END();

  if (CAN_RUN()) {
    RUN();

    uint64_t stored_value = arg2 & result_mask;
    CHECK_EQUAL_64(stored_value, x10);
    CHECK_EQUAL_64(stored_value, x11);
    CHECK_EQUAL_64(stored_value, x12);
    CHECK_EQUAL_64(stored_value, x13);

    // The data fields contain arg2 already then only the bits masked by
    // result_mask are overwritten.
    uint64_t final_expected = (arg2 & ~result_mask) | (expected & result_mask);
    CHECK_EQUAL_64(final_expected, data0[0]);
    CHECK_EQUAL_64(final_expected, data1[0]);
    CHECK_EQUAL_64(final_expected, data2[0]);
    CHECK_EQUAL_64(final_expected, data3[0]);

    if (store_funcs != NULL) {
      CHECK_EQUAL_64(final_expected, data4[0]);
      CHECK_EQUAL_64(final_expected, data5[0]);
    }
  }
}

static void AtomicMemoryXHelper(AtomicMemoryLoadSignature* load_funcs,
                                AtomicMemoryStoreSignature* store_funcs,
                                uint64_t arg1, uint64_t arg2,
                                uint64_t expected) {
  alignas(kXRegSize * 2) uint64_t data0[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data1[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data2[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data3[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data4[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data5[] = {arg2, 0};

  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x20, reinterpret_cast<uintptr_t>(data0));
  __ Mov(x21, reinterpret_cast<uintptr_t>(data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3));

  __ Mov(x0, arg1);
  __ Mov(x1, arg1);
  __ Mov(x2, arg1);
  __ Mov(x3, arg1);

  (masm.*(load_funcs[0]))(x0, x10, MemOperand(x20));
  (masm.*(load_funcs[1]))(x1, x11, MemOperand(x21));
  (masm.*(load_funcs[2]))(x2, x12, MemOperand(x22));
  (masm.*(load_funcs[3]))(x3, x13, MemOperand(x23));

  if (store_funcs != NULL) {
    __ Mov(x24, reinterpret_cast<uintptr_t>(data4));
    __ Mov(x25, reinterpret_cast<uintptr_t>(data5));
    __ Mov(x4, arg1);
    __ Mov(x5, arg1);

    (masm.*(store_funcs[0]))(x4, MemOperand(x24));
    (masm.*(store_funcs[1]))(x5, MemOperand(x25));
  }

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(arg2, x10);
    CHECK_EQUAL_64(arg2, x11);
    CHECK_EQUAL_64(arg2, x12);
    CHECK_EQUAL_64(arg2, x13);

    CHECK_EQUAL_64(expected, data0[0]);
    CHECK_EQUAL_64(expected, data1[0]);
    CHECK_EQUAL_64(expected, data2[0]);
    CHECK_EQUAL_64(expected, data3[0]);

    if (store_funcs != NULL) {
      CHECK_EQUAL_64(expected, data4[0]);
      CHECK_EQUAL_64(expected, data5[0]);
    }
  }
}

// clang-format off
#define MAKE_LOADS(NAME)           \
    {&MacroAssembler::Ld##NAME,    \
     &MacroAssembler::Ld##NAME##a, \
     &MacroAssembler::Ld##NAME##l, \
     &MacroAssembler::Ld##NAME##al}
#define MAKE_STORES(NAME) \
    {&MacroAssembler::St##NAME, &MacroAssembler::St##NAME##l}

#define MAKE_B_LOADS(NAME)          \
    {&MacroAssembler::Ld##NAME##b,  \
     &MacroAssembler::Ld##NAME##ab, \
     &MacroAssembler::Ld##NAME##lb, \
     &MacroAssembler::Ld##NAME##alb}
#define MAKE_B_STORES(NAME) \
    {&MacroAssembler::St##NAME##b, &MacroAssembler::St##NAME##lb}

#define MAKE_H_LOADS(NAME)          \
    {&MacroAssembler::Ld##NAME##h,  \
     &MacroAssembler::Ld##NAME##ah, \
     &MacroAssembler::Ld##NAME##lh, \
     &MacroAssembler::Ld##NAME##alh}
#define MAKE_H_STORES(NAME) \
    {&MacroAssembler::St##NAME##h, &MacroAssembler::St##NAME##lh}
// clang-format on

TEST(atomic_memory_add) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(add);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(add);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(add);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(add);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(add);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(add);

  // The arguments are chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t arg1 = 0x0100001000100101;
  uint64_t arg2 = 0x0200002000200202;
  uint64_t expected = arg1 + arg2;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_clr) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(clr);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(clr);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(clr);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(clr);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(clr);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(clr);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg2 & ~arg1;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_eor) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(eor);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(eor);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(eor);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(eor);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(eor);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(eor);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg1 ^ arg2;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_set) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(set);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(set);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(set);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(set);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(set);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(set);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg1 | arg2;

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_smax) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(smax);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(smax);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(smax);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(smax);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(smax);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(smax);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_smin) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(smin);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(smin);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(smin);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(smin);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(smin);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(smin);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x8100000080108181;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_umax) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(umax);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(umax);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(umax);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(umax);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(umax);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(umax);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x8100000080108181;

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_umin) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(umin);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(umin);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(umin);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(umin);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(umin);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(umin);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_swp) {
  AtomicMemoryLoadSignature loads[] = {
      &MacroAssembler::Swp, &MacroAssembler::Swpa, &MacroAssembler::Swpl,
      &MacroAssembler::Swpal};
  AtomicMemoryLoadSignature b_loads[] = {
      &MacroAssembler::Swpb, &MacroAssembler::Swpab, &MacroAssembler::Swplb,
      &MacroAssembler::Swpalb};
  AtomicMemoryLoadSignature h_loads[] = {
      &MacroAssembler::Swph, &MacroAssembler::Swpah, &MacroAssembler::Swplh,
      &MacroAssembler::Swpalh};

  uint64_t arg1 = 0x0100001000100101;
  uint64_t arg2 = 0x0200002000200202;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  // SWP functions have equivalent signatures to the Atomic Memory LD functions
  // so we can use the same helper but without the ST aliases.
  AtomicMemoryWHelper(b_loads, NULL, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, NULL, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, NULL, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, NULL, arg1, arg2, expected);
}

TEST(process_nan_double) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  double sn = base::bit_cast<double>(0x7FF5555511111111);
  double qn = base::bit_cast<double>(0x7FFAAAAA11111111);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsQuietNaN(qn));

  // The input NaNs after passing through ProcessNaN.
  double sn_proc = base::bit_cast<double>(0x7FFD555511111111);
  double qn_proc = qn;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(qn_proc));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaN, and check that
  // they all handle the NaN correctly.
  __ Fmov(d0, sn);
  __ Fmov(d10, qn);

  // Operations that always propagate NaNs unchanged, even signalling NaNs.
  //   - Signalling NaN
  __ Fmov(d1, d0);
  __ Fabs(d2, d0);
  __ Fneg(d3, d0);
  //   - Quiet NaN
  __ Fmov(d11, d10);
  __ Fabs(d12, d10);
  __ Fneg(d13, d10);

  // Operations that use ProcessNaN.
  //   - Signalling NaN
  __ Fsqrt(d4, d0);
  __ Frinta(d5, d0);
  __ Frintn(d6, d0);
  __ Frintz(d7, d0);
  //   - Quiet NaN
  __ Fsqrt(d14, d10);
  __ Frinta(d15, d10);
  __ Frintn(d16, d10);
  __ Frintz(d17, d10);

  // The behaviour of fcvt is checked in TEST(fcvt_sd).

  END();
  RUN();

  uint64_t qn_raw = base::bit_cast<uint64_t>(qn);
  uint64_t sn_raw = base::bit_cast<uint64_t>(sn);

  //   - Signalling NaN
  CHECK_EQUAL_FP64(sn, d1);
  CHECK_EQUAL_FP64(base::bit_cast<double>(sn_raw & ~kDSignMask), d2);
  CHECK_EQUAL_FP64(base::bit_cast<double>(sn_raw ^ kDSignMask), d3);
  //   - Quiet NaN
  CHECK_EQUAL_FP64(qn, d11);
  CHECK_EQUAL_FP64(base::bit_cast<double>(qn_raw & ~kDSignMask), d12);
  CHECK_EQUAL_FP64(base::bit_cast<double>(qn_raw ^ kDSignMask), d13);

  //   - Signalling NaN
  CHECK_EQUAL_FP64(sn_proc, d4);
  CHECK_EQUAL_FP64(sn_proc, d5);
  CHECK_EQUAL_FP64(sn_proc, d6);
  CHECK_EQUAL_FP64(sn_proc, d7);
  //   - Quiet NaN
  CHECK_EQUAL_FP64(qn_proc, d14);
  CHECK_EQUAL_FP64(qn_proc, d15);
  CHECK_EQUAL_FP64(qn_proc, d16);
  CHECK_EQUAL_FP64(qn_proc, d17);
}

TEST(process_nan_float) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  float sn = base::bit_cast<float>(0x7F951111);
  float qn = base::bit_cast<float>(0x7FEA1111);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsQuietNaN(qn));

  // The input NaNs after passing through ProcessNaN.
  float sn_proc = base::bit_cast<float>(0x7FD51111);
  float qn_proc = qn;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(qn_proc));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaN, and check that
  // they all handle the NaN correctly.
  __ Fmov(s0, sn);
  __ Fmov(s10, qn);

  // Operations that always propagate NaNs unchanged, even signalling NaNs.
  //   - Signalling NaN
  __ Fmov(s1, s0);
  __ Fabs(s2, s0);
  __ Fneg(s3, s0);
  //   - Quiet NaN
  __ Fmov(s11, s10);
  __ Fabs(s12, s10);
  __ Fneg(s13, s10);

  // Operations that use ProcessNaN.
  //   - Signalling NaN
  __ Fsqrt(s4, s0);
  __ Frinta(s5, s0);
  __ Frintn(s6, s0);
  __ Frintz(s7, s0);
  //   - Quiet NaN
  __ Fsqrt(s14, s10);
  __ Frinta(s15, s10);
  __ Frintn(s16, s10);
  __ Frintz(s17, s10);

  // The behaviour of fcvt is checked in TEST(fcvt_sd).

  END();
  RUN();

  uint32_t qn_raw = base::bit_cast<uint32_t>(qn);
  uint32_t sn_raw = base::bit_cast<uint32_t>(sn);
  uint32_t sign_mask = static_cast<uint32_t>(kSSignMask);

  //   - Signalling NaN
  CHECK_EQUAL_FP32(sn, s1);
  CHECK_EQUAL_FP32(base::bit_cast<float>(sn_raw & ~sign_mask), s2);
  CHECK_EQUAL_FP32(base::bit_cast<float>(sn_raw ^ sign_mask), s3);
  //   - Quiet NaN
  CHECK_EQUAL_FP32(qn, s11);
  CHECK_EQUAL_FP32(base::bit_cast<float>(qn_raw & ~sign_mask), s12);
  CHECK_EQUAL_FP32(base::bit_cast<float>(qn_raw ^ sign_mask), s13);

  //   - Signalling NaN
  CHECK_EQUAL_FP32(sn_proc, s4);
  CHECK_EQUAL_FP32(sn_proc, s5);
  CHECK_EQUAL_FP32(sn_proc, s6);
  CHECK_EQUAL_FP32(sn_proc, s7);
  //   - Quiet NaN
  CHECK_EQUAL_FP32(qn_proc, s14);
  CHECK_EQUAL_FP32(qn_proc, s15);
  CHECK_EQUAL_FP32(qn_proc, s16);
  CHECK_EQUAL_FP32(qn_proc, s17);
}


static void ProcessNaNsHelper(double n, double m, double expected) {
  CHECK(std::isnan(n) || std::isnan(m));
  CHECK(std::isnan(expected));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaNs, and check that
  // they all propagate NaNs correctly.
  __ Fmov(d0, n);
  __ Fmov(d1, m);

  __ Fadd(d2, d0, d1);
  __ Fsub(d3, d0, d1);
  __ Fmul(d4, d0, d1);
  __ Fdiv(d5, d0, d1);
  __ Fmax(d6, d0, d1);
  __ Fmin(d7, d0, d1);

  END();
  RUN();

  CHECK_EQUAL_FP64(expected, d2);
  CHECK_EQUAL_FP64(expected, d3);
  CHECK_EQUAL_FP64(expected, d4);
  CHECK_EQUAL_FP64(expected, d5);
  CHECK_EQUAL_FP64(expecte
```