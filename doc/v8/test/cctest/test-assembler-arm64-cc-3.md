Response:
My thinking process to answer the request about the V8 assembler test file goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of `v8/test/cctest/test-assembler-arm64.cc`. Key constraints are to identify the functionality, check if it's Torque, see if it relates to JavaScript, provide examples, consider code logic/assumptions, and highlight common programming errors. The request explicitly mentions this is part 4 of 15 and asks for a summary of functionality.

2. **Initial Analysis of the Code Snippet:** I scanned the provided C++ code. Several key things jumped out:
    * **`TEST(...)` blocks:** This indicates it's a testing file, likely using a testing framework (in this case, V8's internal testing framework).
    * **`INIT_V8()`, `SETUP()`, `START()`, `END()`, `RUN()`:** These are likely boilerplate for setting up and running tests within the V8 environment.
    * **`__ Mov(...)`, `__ Ldr(...)`, `__ Ld2(...)`, `__ Ld3(...)`, `__ Ld4(...)`:**  The double underscore (`__`) prefix strongly suggests these are macros or inline functions representing ARM64 assembly instructions. The names themselves (`Mov`, `Ldr`, `Ld2`, etc.) are reminiscent of ARM instruction mnemonics (Move, Load Register, Load multiple registers).
    * **`v0.V8B()`, `v1.V16B()`, `q0`, `q1`, `x17`, `x19`:** These look like ARM64 register names. `v` registers are typically used for SIMD (NEON) operations. `q` registers are 128-bit NEON registers. `x` registers are general-purpose 64-bit registers. The `.V8B()`, `.V16B()`, etc., likely specify the data type and size of the vector register elements (e.g., 8-bit bytes, 16-bit bytes).
    * **`MemOperand(...)`:** This clearly deals with accessing memory.
    * **`CHECK_EQUAL_...(...)`:** These are assertion macros for verifying the results of the executed code. They compare expected values with the actual contents of registers.

3. **Formulate the Core Functionality:** Based on the above, I concluded that this file *tests the ARM64 assembler in V8*. Specifically, it's testing the functionality of instructions related to loading data from memory into NEON registers. The different `Ld` instructions (`Ld2`, `Ld3`, `Ld4`) likely correspond to loading data into 2, 3, or 4 registers simultaneously. The variations like `_d`, `_q`, `_lane`, `_alllanes`, and `_postindex` suggest different ways of performing these load operations (different data sizes, accessing specific lanes/elements, using post-increment addressing).

4. **Address Specific Questions:**

    * **`.tq` extension:** The code is clearly C++, not Torque.
    * **Relationship to JavaScript:**  The assembler is a low-level component used by the V8 JavaScript engine to generate machine code. While not directly writing JavaScript, this code ensures the underlying code generation works correctly. I devised a simple JavaScript example where the JIT compiler might use these instructions (vector operations).
    * **Code Logic and Assumptions:** The tests involve setting up a memory buffer with known values, executing assembly instructions to load data, and then verifying the loaded data in the registers. I identified the assumptions about memory layout and register usage. I created a simple example of input memory and the expected output in registers for one of the tests.
    * **Common Programming Errors:**  Given the nature of assembler code, I focused on memory access errors (out-of-bounds reads, incorrect alignment), which are common pitfalls.

5. **Structure the Answer:** I decided to organize the answer into the requested sections: functionality, Torque check, JavaScript relation, code logic, common errors, and a summary. This provides a clear and comprehensive explanation.

6. **Refine and Elaborate:** I expanded on the initial points, providing more detail about the specific assembly instructions being tested (e.g., `LD2`, `LD3`, `LD4` and their variants). I made sure the JavaScript example was relevant and easy to understand. For the code logic, I walked through a specific test case, explaining the setup and verification.

7. **Consider the "Part 4 of 15" Context:** Since this is part of a larger set, I assumed the previous parts likely covered other aspects of the ARM64 assembler or related functionalities. The summary for Part 4 specifically focused on the load instructions tested in this snippet.

8. **Review and Edit:** I reviewed the answer for clarity, accuracy, and completeness, ensuring all aspects of the request were addressed. I made sure the language was accessible and avoided overly technical jargon where possible. I double-checked the formatting and the examples.

By following these steps, I could generate a comprehensive and accurate answer that addresses all the user's queries about the given V8 assembler test code.
这是提供的V8源代码文件 `v8/test/cctest/test-assembler-arm64.cc` 的第 4 部分，它主要包含了一系列针对 ARM64 架构汇编器的单元测试。这些测试集中验证了 NEON (Advanced SIMD) 指令中 **加载 (Load)** 操作的正确性，特别是针对 **结构体加载 (Structure Loads)** 的各种变体。

**功能归纳:**

这部分代码的功能是测试 ARM64 汇编器中以下 NEON 加载指令的功能：

* **`Ld2` (Load 2 Registers):**  将内存中的数据交错加载到两个 NEON 寄存器中。测试了标量加载 (`Ld2`), 按 Lane 加载 (`Ld2`), 和加载所有 Lane (`Ld2r`).
* **`Ld3` (Load 3 Registers):** 将内存中的数据交错加载到三个 NEON 寄存器中。测试了标量加载 (`Ld3`), 按 Lane 加载 (`Ld3`), 和加载所有 Lane (`Ld3r`).
* **`Ld4` (Load 4 Registers):** 将内存中的数据交错加载到四个 NEON 寄存器中。测试了标量加载 (`Ld4`), 按 Lane 加载 (`Ld4`), 和加载所有 Lane (`Ld4r`).

这些测试覆盖了不同的数据类型大小 (`B`, `H`, `S`, `D` 代表 Byte, Half-word, Single-word, Double-word) 和不同的寻址模式 (立即数偏移和寄存器后索引)。

**关于文件类型:**

`v8/test/cctest/test-assembler-arm64.cc` 以 `.cc` 结尾，表明它是一个 C++ 源文件，而不是 Torque 文件。如果以 `.tq` 结尾，那它才会是 V8 Torque 源代码。

**与 JavaScript 的关系:**

这段代码直接测试的是 V8 引擎中用于生成 ARM64 机器码的汇编器。当 JavaScript 代码被 V8 编译成机器码时，如果涉及到 SIMD 操作 (例如，使用 `Float32x4` 或 `Int32x4` 等类型)，V8 的代码生成器会使用这些底层的汇编指令。

**JavaScript 示例:**

```javascript
// 假设 JavaScript 代码使用了 SIMD 操作
let a = Float32x4(1.0, 2.0, 3.0, 4.0);
let b = Float32x4(5.0, 6.0, 7.0, 8.0);
let c = a.add(b); // 执行 SIMD 加法

// 当 V8 执行这段代码时，可能会生成类似于测试用例中涉及的 ARM64 NEON 指令，
// 例如，将数组加载到 NEON 寄存器中进行并行计算。
```

虽然 JavaScript 代码本身没有直接的 `Ld2`, `Ld3`, `Ld4` 指令，但 V8 引擎在编译和优化 JavaScript 代码时，会使用这些底层的汇编指令来实现高性能的 SIMD 操作。测试代码确保了这些底层指令在 ARM64 架构上的正确行为。

**代码逻辑推理和假设输入/输出:**

以 `TEST(neon_ld2_d)` 为例：

**假设输入:**

* 内存地址 `src_base + 1` 开始的连续字节，其值为 0, 1, 2, 3, ...
* 初始状态下，NEON 寄存器 `q0` 到 `q15` 的值可能为任意值 (在测试中会被覆盖)。

**代码逻辑:**

1. 将内存地址 `src_base + 1` 加载到寄存器 `x17`。
2. 使用 `__Ld2r(v0.V8B(), v1.V8B(), MemOperand(x17))` 从 `x17` 指向的内存地址加载 16 个字节，交错存储到 `v0` 和 `v1` 寄存器 (每个寄存器 8 个字节)。例如，`v0` 得到字节 1, 3, 5, 7, 9, 11, 13, 15，`v1` 得到字节 2, 4, 6, 8, 10, 12, 14, 16。
3. 递增 `x17`，然后执行其他 `Ld2r` 指令，加载不同大小的数据到不同的寄存器对。

**预期输出 (部分):**

* `q0` 应该包含从内存加载的交错字节，如 `CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0)` 所示，低 64 位为 0，高 64 位为 `0x0101010101010101`。这表明 `v0` 的每个字节都被加载了内存中的第二个字节的值 (索引为 1 的字节)。
* `q1` 应该包含与 `q0` 配对加载的数据，如 `CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1)` 所示。

`CHECK_EQUAL_128` 宏用于验证 NEON 寄存器的 128 位值是否与预期值相等。

**用户常见的编程错误:**

在编写使用 SIMD 指令的代码时，用户可能会犯以下错误：

* **内存对齐错误:**  NEON 指令通常要求数据在内存中是对齐的 (例如，128 位的数据需要 16 字节对齐)。如果数据未对齐，会导致程序崩溃或性能下降。
  ```c++
  uint8_t src[17]; // 假设一个未对齐的起始地址
  uint8_t* ptr = src + 1; // ptr 指向未 16 字节对齐的地址

  // 尝试加载 128 位数据到 NEON 寄存器，可能会出错
  // __ Ld1(q0, MemOperand(reinterpret_cast<intptr_t>(ptr)));
  ```
* **访问越界:**  尝试加载超出分配内存范围的数据会导致程序崩溃或未定义行为。
  ```c++
  uint8_t src[16];
  // 尝试加载超过 16 字节的数据，会导致越界访问
  // __ Ld1(v0.V16B(), MemOperand(reinterpret_cast<intptr_t>(src), 32));
  ```
* **错误的 Lane 索引:**  在使用按 Lane 加载指令时，如果指定的 Lane 索引超出范围，会导致错误。
  ```c++
  uint8_t src[16];
  // v0 是 128 位寄存器，有 16 个 Byte Lane (索引 0-15)
  // 尝试加载到不存在的 Lane 16
  // __ Ld1(v0.B(), 16, MemOperand(reinterpret_cast<intptr_t>(src)));
  ```
* **数据类型不匹配:**  尝试使用与内存中数据类型不匹配的指令进行加载，可能导致数据解析错误。

**总结第 4 部分的功能:**

总而言之，`v8/test/cctest/test-assembler-arm64.cc` 的第 4 部分专注于测试 ARM64 汇编器中用于将结构体数据从内存加载到 NEON 寄存器的指令 (`Ld2`, `Ld3`, `Ld4`) 的各种使用方式和数据大小，确保了 V8 引擎在 ARM64 架构上进行 SIMD 操作时的正确性和可靠性。这些测试覆盖了标量加载、按 Lane 加载以及加载所有 Lane 的情况，并验证了不同数据类型和寻址模式下的行为。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
q0);
  CHECK_EQUAL_128(0x01030507090B0D0F, 0x11131517191B1D1F, q1);
  CHECK_EQUAL_128(0x0100050409080D0C, 0x1110151419181D1C, q2);
  CHECK_EQUAL_128(0x030207060B0A0F0E, 0x131217161B1A1F1E, q3);
  CHECK_EQUAL_128(0x030201000B0A0908, 0x131211101B1A1918, q4);
  CHECK_EQUAL_128(0x070605040F0E0D0C, 0x171615141F1E1D1C, q5);
  CHECK_EQUAL_128(0x0706050403020100, 0x1716151413121110, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1F1E1D1C1B1A1918, q7);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q8);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q10);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q11);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q13);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q15);

  CHECK_EQUAL_64(src_base + 32, x17);
  CHECK_EQUAL_64(src_base + 32, x28);
  CHECK_EQUAL_64(src_base + 32, x19);
  CHECK_EQUAL_64(src_base + 32, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld2_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld2r(v0.V8B(), v1.V8B(), MemOperand(x17));
  __ Add(x17, x17, 2);
  __ Ld2r(v2.V16B(), v3.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v4.V4H(), v5.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v6.V8H(), v7.V8H(), MemOperand(x17));
  __ Add(x17, x17, 4);
  __ Ld2r(v8_.V2S(), v9.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld2r(v10.V4S(), v11.V4S(), MemOperand(x17));
  __ Add(x17, x17, 8);
  __ Ld2r(v12.V2D(), v13.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0303030303030303, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0000000000000000, 0x0504050405040504, q4);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q5);
  CHECK_EQUAL_128(0x0605060506050605, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0C0B0A090C0B0A09, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x100F0E0D100F0E0D, q9);
  CHECK_EQUAL_128(0x0D0C0B0A0D0C0B0A, 0x0D0C0B0A0D0C0B0A, q10);
  CHECK_EQUAL_128(0x11100F0E11100F0E, 0x11100F0E11100F0E, q11);
  CHECK_EQUAL_128(0x1918171615141312, 0x1918171615141312, q12);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x21201F1E1D1C1B1A, q13);
}

TEST(neon_ld2_alllanes_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Mov(x19, 1);
  __ Ld2r(v0.V8B(), v1.V8B(), MemOperand(x17, 2, PostIndex));
  __ Ld2r(v2.V16B(), v3.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v4.V4H(), v5.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v6.V8H(), v7.V8H(), MemOperand(x17, 4, PostIndex));
  __ Ld2r(v8_.V2S(), v9.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld2r(v10.V4S(), v11.V4S(), MemOperand(x17, 8, PostIndex));
  __ Ld2r(v12.V2D(), v13.V2D(), MemOperand(x17, 16, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0303030303030303, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0000000000000000, 0x0504050405040504, q4);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q5);
  CHECK_EQUAL_128(0x0605060506050605, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0C0B0A090C0B0A09, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x100F0E0D100F0E0D, q9);
  CHECK_EQUAL_128(0x0D0C0B0A0D0C0B0A, 0x0D0C0B0A0D0C0B0A, q10);
  CHECK_EQUAL_128(0x11100F0E11100F0E, 0x11100F0E11100F0E, q11);
  CHECK_EQUAL_128(0x1918171615141312, 0x1918171615141312, q12);
  CHECK_EQUAL_128(0x21201F1E1D1C1B1A, 0x21201F1E1D1C1B1A, q13);
  CHECK_EQUAL_64(src_base + 34, x17);
}

TEST(neon_ld3_d) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld3(v2.V8B(), v3.V8B(), v4.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v5.V8B(), v6.V8B(), v7.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v8_.V4H(), v9.V4H(), v10.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0, 0x1211100F06050403, q31);
  CHECK_EQUAL_128(0, 0x161514130A090807, q0);
  CHECK_EQUAL_128(0, 0x1A1918170E0D0C0B, q1);
}

TEST(neon_ld3_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld3(v2.V8B(), v3.V8B(), v4.V8B(), MemOperand(x17, x22, PostIndex));
  __ Ld3(v5.V8B(), v6.V8B(), v7.V8B(), MemOperand(x28, 24, PostIndex));
  __ Ld3(v8_.V4H(), v9.V4H(), v10.V4H(), MemOperand(x19, 24, PostIndex));
  __ Ld3(v11.V2S(), v12.V2S(), v13.V2S(), MemOperand(x20, 24, PostIndex));
  __ Ld3(v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x21, 24, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0, 0x1312111007060504, q31);
  CHECK_EQUAL_128(0, 0x171615140B0A0908, q0);
  CHECK_EQUAL_128(0, 0x1B1A19180F0E0D0C, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 24, x28);
  CHECK_EQUAL_64(src_base + 2 + 24, x19);
  CHECK_EQUAL_64(src_base + 3 + 24, x20);
  CHECK_EQUAL_64(src_base + 4 + 24, x21);
}

TEST(neon_ld3_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld3(v2.V16B(), v3.V16B(), v4.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v8_.V8H(), v9.V8H(), v10.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v11.V4S(), v12.V4S(), v13.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3(v31.V2D(), v0.V2D(), v1.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x2D2A2724211E1B18, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0x302D2A2724211E1B, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0x2D2C272621201B1A, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0x2F2E292823221D1C, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0x31302B2A25241F1E, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0x2A2928271E1D1C1B, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0x2E2D2C2B2221201F, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0x3231302F26252423, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x131211100F0E0D0C, q0);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x1B1A191817161514, q1);
}

TEST(neon_ld3_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);

  __ Ld3(v2.V16B(), v3.V16B(), v4.V16B(), MemOperand(x17, x22, PostIndex));
  __ Ld3(v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x28, 48, PostIndex));
  __ Ld3(v8_.V8H(), v9.V8H(), v10.V8H(), MemOperand(x19, 48, PostIndex));
  __ Ld3(v11.V4S(), v12.V4S(), v13.V4S(), MemOperand(x20, 48, PostIndex));
  __ Ld3(v31.V2D(), v0.V2D(), v1.V2D(), MemOperand(x21, 48, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x2D2A2724211E1B18, 0x15120F0C09060300, q2);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q3);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q4);
  CHECK_EQUAL_128(0x2E2B2825221F1C19, 0x1613100D0A070401, q5);
  CHECK_EQUAL_128(0x2F2C292623201D1A, 0x1714110E0B080502, q6);
  CHECK_EQUAL_128(0x302D2A2724211E1B, 0x1815120F0C090603, q7);
  CHECK_EQUAL_128(0x2D2C272621201B1A, 0x15140F0E09080302, q8);
  CHECK_EQUAL_128(0x2F2E292823221D1C, 0x171611100B0A0504, q9);
  CHECK_EQUAL_128(0x31302B2A25241F1E, 0x191813120D0C0706, q10);
  CHECK_EQUAL_128(0x2A2928271E1D1C1B, 0x1211100F06050403, q11);
  CHECK_EQUAL_128(0x2E2D2C2B2221201F, 0x161514130A090807, q12);
  CHECK_EQUAL_128(0x3231302F26252423, 0x1A1918170E0D0C0B, q13);
  CHECK_EQUAL_128(0x232221201F1E1D1C, 0x0B0A090807060504, q31);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x131211100F0E0D0C, q0);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x1B1A191817161514, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 48, x28);
  CHECK_EQUAL_64(src_base + 2 + 48, x19);
  CHECK_EQUAL_64(src_base + 3 + 48, x20);
  CHECK_EQUAL_64(src_base + 4 + 48, x21);
}

TEST(neon_ld3_lane) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();

  // Test loading whole register by element.
  __ Mov(x17, src_base);
  for (int i = 15; i >= 0; i--) {
    __ Ld3(v0.B(), v1.B(), v2.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld3(v3.H(), v4.H(), v5.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld3(v6.S(), v7.S(), v8_.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld3(v9.D(), v10.D(), v11.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Mov(x4, x17);
  __ Ldr(q12, MemOperand(x4, 16, PostIndex));
  __ Ldr(q13, MemOperand(x4, 16, PostIndex));
  __ Ldr(q14, MemOperand(x4));
  __ Ld3(v12.B(), v13.B(), v14.B(), 4, MemOperand(x17));
  __ Mov(x5, x17);
  __ Ldr(q15, MemOperand(x5, 16, PostIndex));
  __ Ldr(q16, MemOperand(x5, 16, PostIndex));
  __ Ldr(q17, MemOperand(x5));
  __ Ld3(v15.H(), v16.H(), v17.H(), 3, MemOperand(x17));
  __ Mov(x6, x17);
  __ Ldr(q18, MemOperand(x6, 16, PostIndex));
  __ Ldr(q19, MemOperand(x6, 16, PostIndex));
  __ Ldr(q20, MemOperand(x6));
  __ Ld3(v18.S(), v19.S(), v20.S(), 2, MemOperand(x17));
  __ Mov(x7, x17);
  __ Ldr(q21, MemOperand(x7, 16, PostIndex));
  __ Ldr(q22, MemOperand(x7, 16, PostIndex));
  __ Ldr(q23, MemOperand(x7));
  __ Ld3(v21.D(), v22.D(), v23.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0102030405060708, 0x090A0B0C0D0E0F10, q1);
  CHECK_EQUAL_128(0x0203040506070809, 0x0A0B0C0D0E0F1011, q2);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q3);
  CHECK_EQUAL_128(0x0302040305040605, 0x0706080709080A09, q4);
  CHECK_EQUAL_128(0x0504060507060807, 0x09080A090B0A0C0B, q5);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q6);
  CHECK_EQUAL_128(0x0706050408070605, 0x090807060A090807, q7);
  CHECK_EQUAL_128(0x0B0A09080C0B0A09, 0x0D0C0B0A0E0D0C0B, q8);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x100F0E0D0C0B0A09, q10);
  CHECK_EQUAL_128(0x1716151413121110, 0x1817161514131211, q11);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q13);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q15);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q16);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q17);
}

TEST(neon_ld3_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();

  // Test loading whole register by element.
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Mov(x19, src_base);
  __ Mov(x20, src_base);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);
  for (int i = 15; i >= 0; i--) {
    __ Ld3(v0.B(), v1.B(), v2.B(), i, MemOperand(x17, 3, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld3(v3.H(), v4.H(), v5.H(), i, MemOperand(x28, 6, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld3(v6.S(), v7.S(), v8_.S(), i, MemOperand(x19, 12, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld3(v9.D(), v10.D(), v11.D(), i, MemOperand(x20, 24, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Mov(x4, x21);
  __ Ldr(q12, MemOperand(x4, 16, PostIndex));
  __ Ldr(q13, MemOperand(x4, 16, PostIndex));
  __ Ldr(q14, MemOperand(x4));
  __ Ld3(v12.B(), v13.B(), v14.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x5, x22);
  __ Ldr(q15, MemOperand(x5, 16, PostIndex));
  __ Ldr(q16, MemOperand(x5, 16, PostIndex));
  __ Ldr(q17, MemOperand(x5));
  __ Ld3(v15.H(), v16.H(), v17.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x6, x23);
  __ Ldr(q18, MemOperand(x6, 16, PostIndex));
  __ Ldr(q19, MemOperand(x6, 16, PostIndex));
  __ Ldr(q20, MemOperand(x6));
  __ Ld3(v18.S(), v19.S(), v20.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x7, x24);
  __ Ldr(q21, MemOperand(x7, 16, PostIndex));
  __ Ldr(q22, MemOperand(x7, 16, PostIndex));
  __ Ldr(q23, MemOperand(x7));
  __ Ld3(v21.D(), v22.D(), v23.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x000306090C0F1215, 0x181B1E2124272A2D, q0);
  CHECK_EQUAL_128(0x0104070A0D101316, 0x191C1F2225282B2E, q1);
  CHECK_EQUAL_128(0x0205080B0E111417, 0x1A1D202326292C2F, q2);
  CHECK_EQUAL_128(0x010007060D0C1312, 0x19181F1E25242B2A, q3);
  CHECK_EQUAL_128(0x030209080F0E1514, 0x1B1A212027262D2C, q4);
  CHECK_EQUAL_128(0x05040B0A11101716, 0x1D1C232229282F2E, q5);
  CHECK_EQUAL_128(0x030201000F0E0D0C, 0x1B1A191827262524, q6);
  CHECK_EQUAL_128(0x0706050413121110, 0x1F1E1D1C2B2A2928, q7);
  CHECK_EQUAL_128(0x0B0A090817161514, 0x232221202F2E2D2C, q8);
  CHECK_EQUAL_128(0x0706050403020100, 0x1F1E1D1C1B1A1918, q9);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x2726252423222120, q10);
  CHECK_EQUAL_128(0x1716151413121110, 0x2F2E2D2C2B2A2928, q11);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q12);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q13);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q14);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q15);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q16);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q17);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q23);

  CHECK_EQUAL_64(src_base + 48, x17);
  CHECK_EQUAL_64(src_base + 48, x28);
  CHECK_EQUAL_64(src_base + 48, x19);
  CHECK_EQUAL_64(src_base + 48, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld3_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld3r(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x17));
  __ Add(x17, x17, 3);
  __ Ld3r(v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v6.V4H(), v7.V4H(), v8_.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v9.V8H(), v10.V8H(), v11.V8H(), MemOperand(x17));
  __ Add(x17, x17, 6);
  __ Ld3r(v12.V2S(), v13.V2S(), v14.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld3r(v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17));
  __ Add(x17, x17, 12);
  __ Ld3r(v18.V2D(), v19.V2D(), v20.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0000000000000000, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0000000000000000, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0A090A090A090A09, q8);
  CHECK_EQUAL_128(0x0706070607060706, 0x0706070607060706, q9);
  CHECK_EQUAL_128(0x0908090809080908, 0x0908090809080908, q10);
  CHECK_EQUAL_128(0x0B0A0B0A0B0A0B0A, 0x0B0A0B0A0B0A0B0A, q11);
  CHECK_EQUAL_128(0x0000000000000000, 0x0F0E0D0C0F0E0D0C, q12);
  CHECK_EQUAL_128(0x0000000000000000, 0x1312111013121110, q13);
  CHECK_EQUAL_128(0x0000000000000000, 0x1716151417161514, q14);
  CHECK_EQUAL_128(0x100F0E0D100F0E0D, 0x100F0E0D100F0E0D, q15);
  CHECK_EQUAL_128(0x1413121114131211, 0x1413121114131211, q16);
  CHECK_EQUAL_128(0x1817161518171615, 0x1817161518171615, q17);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x201F1E1D1C1B1A19, q18);
  CHECK_EQUAL_128(0x2827262524232221, 0x2827262524232221, q19);
  CHECK_EQUAL_128(0x302F2E2D2C2B2A29, 0x302F2E2D2C2B2A29, q20);
}

TEST(neon_ld3_alllanes_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Mov(x19, 1);
  __ Ld3r(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x17, 3, PostIndex));
  __ Ld3r(v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v6.V4H(), v7.V4H(), v8_.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v9.V8H(), v10.V8H(), v11.V8H(), MemOperand(x17, 6, PostIndex));
  __ Ld3r(v12.V2S(), v13.V2S(), v14.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld3r(v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17, 12, PostIndex));
  __ Ld3r(v18.V2D(), v19.V2D(), v20.V2D(), MemOperand(x17, 24, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0404040404040404, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0000000000000000, 0x0605060506050605, q6);
  CHECK_EQUAL_128(0x0000000000000000, 0x0807080708070807, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0A090A090A090A09, q8);
  CHECK_EQUAL_128(0x0706070607060706, 0x0706070607060706, q9);
  CHECK_EQUAL_128(0x0908090809080908, 0x0908090809080908, q10);
  CHECK_EQUAL_128(0x0B0A0B0A0B0A0B0A, 0x0B0A0B0A0B0A0B0A, q11);
  CHECK_EQUAL_128(0x0000000000000000, 0x0F0E0D0C0F0E0D0C, q12);
  CHECK_EQUAL_128(0x0000000000000000, 0x1312111013121110, q13);
  CHECK_EQUAL_128(0x0000000000000000, 0x1716151417161514, q14);
  CHECK_EQUAL_128(0x100F0E0D100F0E0D, 0x100F0E0D100F0E0D, q15);
  CHECK_EQUAL_128(0x1413121114131211, 0x1413121114131211, q16);
  CHECK_EQUAL_128(0x1817161518171615, 0x1817161518171615, q17);
  CHECK_EQUAL_128(0x201F1E1D1C1B1A19, 0x201F1E1D1C1B1A19, q18);
  CHECK_EQUAL_128(0x2827262524232221, 0x2827262524232221, q19);
  CHECK_EQUAL_128(0x302F2E2D2C2B2A29, 0x302F2E2D2C2B2A29, q20);
}

TEST(neon_ld4_d) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld4(v2.V8B(), v3.V8B(), v4.V8B(), v5.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v6.V8B(), v7.V8B(), v8_.V8B(), v9.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v10.V4H(), v11.V4H(), v12.V4H(), v13.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0, 0x1615141306050403, q30);
  CHECK_EQUAL_128(0, 0x1A1918170A090807, q31);
  CHECK_EQUAL_128(0, 0x1E1D1C1B0E0D0C0B, q0);
  CHECK_EQUAL_128(0, 0x2221201F1211100F, q1);
}

TEST(neon_ld4_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[32 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);
  __ Ld4(v2.V8B(), v3.V8B(), v4.V8B(), v5.V8B(),
         MemOperand(x17, x22, PostIndex));
  __ Ld4(v6.V8B(), v7.V8B(), v8_.V8B(), v9.V8B(),
         MemOperand(x28, 32, PostIndex));
  __ Ld4(v10.V4H(), v11.V4H(), v12.V4H(), v13.V4H(),
         MemOperand(x19, 32, PostIndex));
  __ Ld4(v14.V2S(), v15.V2S(), v16.V2S(), v17.V2S(),
         MemOperand(x20, 32, PostIndex));
  __ Ld4(v30.V2S(), v31.V2S(), v0.V2S(), v1.V2S(),
         MemOperand(x21, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0, 0x1716151407060504, q30);
  CHECK_EQUAL_128(0, 0x1B1A19180B0A0908, q31);
  CHECK_EQUAL_128(0, 0x1F1E1D1C0F0E0D0C, q0);
  CHECK_EQUAL_128(0, 0x2322212013121110, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 32, x28);
  CHECK_EQUAL_64(src_base + 2 + 32, x19);
  CHECK_EQUAL_64(src_base + 3 + 32, x20);
  CHECK_EQUAL_64(src_base + 4 + 32, x21);
}

TEST(neon_ld4_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ld4(v2.V16B(), v3.V16B(), v4.V16B(), v5.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v6.V16B(), v7.V16B(), v8_.V16B(), v9.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v10.V8H(), v11.V8H(), v12.V8H(), v13.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v14.V4S(), v15.V4S(), v16.V4S(), v17.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4(v18.V2D(), v19.V2D(), v20.V2D(), v21.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x3C3834302C282420, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0x403C3834302C2824, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0x3B3A33322B2A2322, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0x3D3C35342D2C2524, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0x3F3E37362F2E2726, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0x4140393831302928, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0x3635343326252423, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0x3A3938372A292827, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0x3E3D3C3B2E2D2C2B, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0x4241403F3231302F, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x0B0A090807060504, q18);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x131211100F0E0D0C, q19);
  CHECK_EQUAL_128(0x3B3A393837363534, 0x1B1A191817161514, q20);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x232221201F1E1D1C, q21);
}

TEST(neon_ld4_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 4];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base + 1);
  __ Mov(x19, src_base + 2);
  __ Mov(x20, src_base + 3);
  __ Mov(x21, src_base + 4);
  __ Mov(x22, 1);

  __ Ld4(v2.V16B(), v3.V16B(), v4.V16B(), v5.V16B(),
         MemOperand(x17, x22, PostIndex));
  __ Ld4(v6.V16B(), v7.V16B(), v8_.V16B(), v9.V16B(),
         MemOperand(x28, 64, PostIndex));
  __ Ld4(v10.V8H(), v11.V8H(), v12.V8H(), v13.V8H(),
         MemOperand(x19, 64, PostIndex));
  __ Ld4(v14.V4S(), v15.V4S(), v16.V4S(), v17.V4S(),
         MemOperand(x20, 64, PostIndex));
  __ Ld4(v30.V2D(), v31.V2D(), v0.V2D(), v1.V2D(),
         MemOperand(x21, 64, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x3C3834302C282420, 0x1C1814100C080400, q2);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q3);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q4);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q5);
  CHECK_EQUAL_128(0x3D3935312D292521, 0x1D1915110D090501, q6);
  CHECK_EQUAL_128(0x3E3A36322E2A2622, 0x1E1A16120E0A0602, q7);
  CHECK_EQUAL_128(0x3F3B37332F2B2723, 0x1F1B17130F0B0703, q8);
  CHECK_EQUAL_128(0x403C3834302C2824, 0x201C1814100C0804, q9);
  CHECK_EQUAL_128(0x3B3A33322B2A2322, 0x1B1A13120B0A0302, q10);
  CHECK_EQUAL_128(0x3D3C35342D2C2524, 0x1D1C15140D0C0504, q11);
  CHECK_EQUAL_128(0x3F3E37362F2E2726, 0x1F1E17160F0E0706, q12);
  CHECK_EQUAL_128(0x4140393831302928, 0x2120191811100908, q13);
  CHECK_EQUAL_128(0x3635343326252423, 0x1615141306050403, q14);
  CHECK_EQUAL_128(0x3A3938372A292827, 0x1A1918170A090807, q15);
  CHECK_EQUAL_128(0x3E3D3C3B2E2D2C2B, 0x1E1D1C1B0E0D0C0B, q16);
  CHECK_EQUAL_128(0x4241403F3231302F, 0x2221201F1211100F, q17);
  CHECK_EQUAL_128(0x2B2A292827262524, 0x0B0A090807060504, q30);
  CHECK_EQUAL_128(0x333231302F2E2D2C, 0x131211100F0E0D0C, q31);
  CHECK_EQUAL_128(0x3B3A393837363534, 0x1B1A191817161514, q0);
  CHECK_EQUAL_128(0x434241403F3E3D3C, 0x232221201F1E1D1C, q1);

  CHECK_EQUAL_64(src_base + 1, x17);
  CHECK_EQUAL_64(src_base + 1 + 64, x28);
  CHECK_EQUAL_64(src_base + 2 + 64, x19);
  CHECK_EQUAL_64(src_base + 3 + 64, x20);
  CHECK_EQUAL_64(src_base + 4 + 64, x21);
}

TEST(neon_ld4_lane) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();

  // Test loading whole register by element.
  __ Mov(x17, src_base);
  for (int i = 15; i >= 0; i--) {
    __ Ld4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld4(v4.H(), v5.H(), v6.H(), v7.H(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld4(v8_.S(), v9.S(), v10.S(), v11.S(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  __ Mov(x17, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld4(v12.D(), v13.D(), v14.D(), v15.D(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }

  // Test loading a single element into an initialised register.
  __ Mov(x17, src_base);
  __ Mov(x4, x17);
  __ Ldr(q16, MemOperand(x4, 16, PostIndex));
  __ Ldr(q17, MemOperand(x4, 16, PostIndex));
  __ Ldr(q18, MemOperand(x4, 16, PostIndex));
  __ Ldr(q19, MemOperand(x4));
  __ Ld4(v16.B(), v17.B(), v18.B(), v19.B(), 4, MemOperand(x17));

  __ Mov(x5, x17);
  __ Ldr(q20, MemOperand(x5, 16, PostIndex));
  __ Ldr(q21, MemOperand(x5, 16, PostIndex));
  __ Ldr(q22, MemOperand(x5, 16, PostIndex));
  __ Ldr(q23, MemOperand(x5));
  __ Ld4(v20.H(), v21.H(), v22.H(), v23.H(), 3, MemOperand(x17));

  __ Mov(x6, x17);
  __ Ldr(q24, MemOperand(x6, 16, PostIndex));
  __ Ldr(q25, MemOperand(x6, 16, PostIndex));
  __ Ldr(q26, MemOperand(x6, 16, PostIndex));
  __ Ldr(q27, MemOperand(x6));
  __ Ld4(v24.S(), v25.S(), v26.S(), v27.S(), 2, MemOperand(x17));

  __ Mov(x7, x17);
  __ Ldr(q28, MemOperand(x7, 16, PostIndex));
  __ Ldr(q29, MemOperand(x7, 16, PostIndex));
  __ Ldr(q30, MemOperand(x7, 16, PostIndex));
  __ Ldr(q31, MemOperand(x7));
  __ Ld4(v28.D(), v29.D(), v30.D(), v31.D(), 1, MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0102030405060708, 0x090A0B0C0D0E0F10, q1);
  CHECK_EQUAL_128(0x0203040506070809, 0x0A0B0C0D0E0F1011, q2);
  CHECK_EQUAL_128(0x030405060708090A, 0x0B0C0D0E0F101112, q3);
  CHECK_EQUAL_128(0x0100020103020403, 0x0504060507060807, q4);
  CHECK_EQUAL_128(0x0302040305040605, 0x0706080709080A09, q5);
  CHECK_EQUAL_128(0x0504060507060807, 0x09080A090B0A0C0B, q6);
  CHECK_EQUAL_128(0x0706080709080A09, 0x0B0A0C0B0D0C0E0D, q7);
  CHECK_EQUAL_128(0x0302010004030201, 0x0504030206050403, q8);
  CHECK_EQUAL_128(0x0706050408070605, 0x090807060A090807, q9);
  CHECK_EQUAL_128(0x0B0A09080C0B0A09, 0x0D0C0B0A0E0D0C0B, q10);
  CHECK_EQUAL_128(0x0F0E0D0C100F0E0D, 0x11100F0E1211100F, q11);
  CHECK_EQUAL_128(0x0706050403020100, 0x0807060504030201, q12);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x100F0E0D0C0B0A09, q13);
  CHECK_EQUAL_128(0x1716151413121110, 0x1817161514131211, q14);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x201F1E1D1C1B1A19, q15);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q16);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q17);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q18);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736350333323130, q19);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q20);
  CHECK_EQUAL_128(0x
```