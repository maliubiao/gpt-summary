Response:
The user wants a summary of the provided C++ code snippet from `v8/test/cctest/test-assembler-arm64.cc`.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code consists of multiple `TEST` blocks. Each `TEST` block seems to be testing a specific ARM64 assembly instruction or a combination of instructions, primarily focusing on memory access and SIMD (NEON) operations.

2. **Categorize the Tests:**  The test names provide clues about the instructions being tested. We can group them into categories:
    * **NEON Store Instructions (ST1, ST2, ST3, ST4):** These instructions store SIMD register values to memory. The suffixes like `_d` and `_q` likely indicate the size of the data being stored (doubleword and quadword). `postindex` indicates the address register is updated after the store.
    * **NEON Destructive Operations:** Tests with "destructive" in their name (`neon_destructive_minmaxp`, `neon_destructive_tbl`, `neon_destructive_tbx`, `neon_destructive_fcvtl`) likely test instructions where the destination register might also be a source operand and is modified in place.
    * **Load/Store Pair Instructions (LDP, STP):**  These instructions load or store pairs of registers. The suffixes like `_float`, `_double`, `_quad` indicate the data type, and `_offset` and `_preindex` refer to different addressing modes.

3. **Analyze Individual Test Cases:**  For each test case, observe the following:
    * **Initialization:** Data is often initialized in `src` arrays.
    * **Assembly Instructions:** Focus on the instructions being tested and the registers involved.
    * **Memory Operations:** Pay attention to `MemOperand` and addressing modes (pre/post-index, offset).
    * **Assertions:** The `CHECK_EQUAL_*` macros verify the expected outcome in registers and memory.

4. **Infer High-Level Functionality:** Based on the tested instructions, we can infer the broader functionality of the code:
    * **Testing NEON store instructions with different data sizes and addressing modes.**
    * **Testing NEON instructions that modify their input operands.**
    * **Testing load and store pair instructions for different data types and addressing modes.**

5. **Address Specific User Questions:**
    * **Is it Torque?** The filename ends in `.cc`, not `.tq`, so it's C++.
    * **Relation to JavaScript?** This code directly tests the ARM64 assembler in V8. The assembler is used by the JIT compiler to generate native machine code from JavaScript. So, indirectly, it's crucial for JavaScript performance.
    * **JavaScript Example:**  A JavaScript example demonstrating the use of SIMD operations can be provided.
    * **Code Logic and I/O:** The `CHECK_EQUAL_*` macros serve as the output verification based on the input data initialized in the `src` arrays. We can provide a simple example with initial input and expected register/memory output.
    * **Common Programming Errors:**  Relate the tested operations to potential errors, such as incorrect address calculations, buffer overflows, and data type mismatches.

6. **Synthesize the Summary:** Combine the observations and inferences into a concise summary, addressing all aspects of the prompt. Emphasize that it's a low-level test suite for the ARM64 assembler.

7. **Structure the Output:** Organize the information logically, addressing each part of the user's request clearly. Use headings and bullet points for readability.
这是 V8 源代码 `v8/test/cctest/test-assembler-arm64.cc` 的一部分，它是一个 **C++** 文件，用于测试 V8 JavaScript 引擎中 **ARM64 架构** 的 **汇编器 (`Assembler`)** 的功能。

**功能归纳:**

这部分代码主要测试了 ARM64 架构下 NEON (Advanced SIMD) 扩展指令中的**存储指令 (Store Instructions)** 以及一些其他的内存操作指令，例如 **加载/存储对指令 (Load/Store Pair Instructions)**，并涵盖了不同的数据大小、寻址模式和破坏性操作。

更具体地说，这部分测试涵盖了以下功能：

1. **NEON 存储指令 (St1, St2, St3, St4):**
   - 测试了将 SIMD 寄存器中的数据存储到内存的不同方式。
   - 包括了存储 1 个、2 个、3 个和 4 个 SIMD 寄存器的场景。
   - 测试了不同的数据类型和大小，如字节 (`B`)、半字 (`H`)、单字 (`S`) 和双字 (`D`)，以及 128 位 (`Q`)。
   - 测试了 **后索引寻址 (PostIndex)** 模式，其中存储器地址在操作后更新。

2. **NEON 破坏性操作 (Destructive Operations):**
   - 测试了一些 NEON 指令，这些指令的目标寄存器同时也是源寄存器之一，执行后会修改源寄存器的内容。
   - 涵盖了最小值/最大值配对指令 (`Sminp`, `Smaxp`, `Uminp`, `Umaxp`)。
   - 涵盖了表查找指令 (`Tbl`, `Tbx`)。
   - 涵盖了浮点转换指令 (`Fcvtl`)，用于将低精度浮点数转换为高精度浮点数。

3. **加载/存储对指令 (Ldp, Stp):**
   - 测试了成对加载和存储寄存器的指令。
   - 包括了加载和存储浮点数 (`float`)、双精度浮点数 (`double`) 和 128 位值 (`quad`)。
   - 测试了不同的寻址模式，如 **偏移寻址 (Offset)** 和 **预索引寻址 (PreIndex)**。

**关于文件类型:**

`v8/test/cctest/test-assembler-arm64.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

**与 JavaScript 的关系:**

虽然这段代码本身不是 JavaScript，但它直接关系到 V8 如何执行 JavaScript 代码。V8 的 JIT (Just-In-Time) 编译器会将 JavaScript 代码转换为机器码，而这个过程会使用到 `Assembler` 来生成针对特定架构（如 ARM64）的汇编指令。

**JavaScript 例子 (间接说明):**

尽管无法直接用 JavaScript 代码对应到这些低级的汇编指令测试，但我们可以通过一个 JavaScript 例子来理解 NEON 指令所处理的 SIMD (Single Instruction, Multiple Data) 概念：

```javascript
// JavaScript 示例，展示 SIMD 的概念
const a = [1, 2, 3, 4];
const b = [5, 6, 7, 8];
const result = [];

// 传统方式：逐个元素相加
for (let i = 0; i < a.length; i++) {
  result.push(a[i] + b[i]);
}
console.log(result); // 输出: [6, 8, 10, 12]

// 使用 SIMD (V8 内部使用，JavaScript 层面没有直接暴露)
// 理论上，NEON 指令可以一次性将 a 和 b 数组中的多个元素相加
// 类似于： SIMD_ADD(a_vector, b_vector)
```

在这个 JavaScript 例子中，SIMD 的思想是并行处理多个数据。`v8/test/cctest/test-assembler-arm64.cc` 中测试的 NEON 指令就是在硬件层面实现这种并行处理的关键。

**代码逻辑推理 (假设输入与输出):**

以 `TEST(neon_st1_d_postindex)` 中的一段代码为例：

```c++
  __ Mov(x19, -32);
  __ Mov(x20, -48);
  __ Mov(x21, -64);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17, 16, PostIndex));
```

**假设输入:**

- 寄存器 `x17` 包含内存地址 `src_base` (指向 `src` 数组的起始位置)。
- SIMD 寄存器 `v0` 包含值 `0x0F0E0D0C0B0A09080706050403020100` (以字节为单位)。

**代码逻辑:**

1. `__ Ldr(q0, MemOperand(x17, 16, PostIndex));`: 从 `x17` 指向的地址加载 128 位数据到 `q0`，并将 `x17` 的值增加 16。重复此操作四次，将 `src` 数组的前 64 字节加载到 `q0`, `q1`, `q2`, `q3`。
2. `__ St1(v0.V16B(), MemOperand(x17, 16, PostIndex));`: 将 `v0` 寄存器中的 16 个字节存储到 `x17` 指向的地址，并将 `x17` 的值增加 16。

**假设输出:**

- 存储操作会将 `v0` 中的字节写入到 `src` 数组的某个位置。
- `CHECK_EQUAL_128` 宏会验证加载到 `q16` 到 `q25` 寄存器的值是否与预期相符。这些预期值通常是从 `src` 数组中加载的，在执行存储指令后，某些值会被覆盖。

**用户常见的编程错误 (与测试相关的):**

- **错误的内存地址计算:** 在使用偏移量或索引时，计算错误的内存地址可能导致数据写入到错误的位置，或者读取到错误的数据，导致程序崩溃或产生不可预测的结果。例如，在 `MemOperand(x17, 16, PostIndex)` 中，如果 `x17` 的初始值或偏移量计算错误，就会访问到错误的内存。
- **缓冲区溢出:**  存储操作写入的数据超过了目标缓冲区的边界。例如，如果 `v0` 包含的数据量很大，而 `x17` 指向的内存空间不足以容纳，就会发生缓冲区溢出。
- **数据类型不匹配:**  尝试将不同大小或类型的寄存器数据存储到内存中，可能导致数据丢失或解释错误。例如，尝试将一个 128 位的 SIMD 寄存器存储到一个只能容纳 64 位的内存位置。
- **未初始化的内存或寄存器:** 在加载数据之前，目标内存或寄存器可能包含垃圾数据，导致程序行为不可预测。

**例子说明 (常见的编程错误):**

```c++
// 假设 src 数组大小为 64 字节
uint8_t src[64];
uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

// 错误示例 1: 错误的偏移量，可能导致越界写入
__ St1(v0.V16B(), MemOperand(x17, 100)); // 如果 x17 指向 src_base，则会越界写入

// 错误示例 2: 数据类型不匹配
uint64_t dest;
__ Str(v0.D[0], MemOperand(x18)); // v0.D[0] 是 64 位，但可能误以为是更大的类型

// 错误示例 3: 忘记更新地址导致覆盖
__ St1(v0.V16B(), MemOperand(x17));
__ St1(v1.V16B(), MemOperand(x17)); // 可能会覆盖之前存储的数据，如果期望存储到不同位置

```

**总结:**

这部分 `v8/test/cctest/test-assembler-arm64.cc` 代码是 V8 引擎中用于测试 ARM64 汇编器功能的关键组成部分，专注于验证 NEON 存储指令和加载/存储对指令在不同场景下的正确性，这对于确保 V8 在 ARM64 架构上高效且稳定地执行 JavaScript 代码至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
__ Mov(x19, -32);
  __ Mov(x20, -48);
  __ Mov(x21, -64);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17, 16, PostIndex));
  __ Ldr(q16, MemOperand(x17, x28));

  __ St1(v0.V8H(), v1.V8H(), MemOperand(x17, 32, PostIndex));
  __ Ldr(q17, MemOperand(x17, x19));
  __ Ldr(q18, MemOperand(x17, x28));

  __ St1(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x17, 48, PostIndex));
  __ Ldr(q19, MemOperand(x17, x20));
  __ Ldr(q20, MemOperand(x17, x19));
  __ Ldr(q21, MemOperand(x17, x28));

  __ St1(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(),
         MemOperand(x17, 64, PostIndex));
  __ Ldr(q22, MemOperand(x17, x21));
  __ Ldr(q23, MemOperand(x17, x20));
  __ Ldr(q24, MemOperand(x17, x19));
  __ Ldr(q25, MemOperand(x17, x28));

  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q18);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q19);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q20);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q21);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q23);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q25);
}

TEST(neon_st2_d) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V8B(), v1.V8B(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St2(v0.V4H(), v1.V4H(), MemOperand(x19));
  __ Add(x19, x19, 11);
  __ St2(v0.V2S(), v1.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q0);
  CHECK_EQUAL_128(0x0504131203021110, 0x0100151413121110, q1);
  CHECK_EQUAL_128(0x1615140706050413, 0x1211100302010014, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323117, q3);
}

TEST(neon_st2_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V8B(), v1.V8B(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V4H(), v1.V4H(), MemOperand(x19, 16, PostIndex));
  __ St2(v0.V2S(), v1.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1405041312030211, 0x1001000211011000, q0);
  CHECK_EQUAL_128(0x0605041312111003, 0x0201001716070615, q1);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726251716151407, q2);
}

TEST(neon_st2_q) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V16B(), v1.V16B(), MemOperand(x19));
  __ Add(x19, x19, 8);
  __ St2(v0.V8H(), v1.V8H(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St2(v0.V4S(), v1.V4S(), MemOperand(x19));
  __ Add(x19, x19, 2);
  __ St2(v0.V2D(), v1.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1312030211100100, 0x1303120211011000, q0);
  CHECK_EQUAL_128(0x01000B0A19180908, 0x1716070615140504, q1);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q2);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0F0E0D0C0B0A0908, q3);
}

TEST(neon_st2_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));

  __ St2(v0.V16B(), v1.V16B(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V8H(), v1.V8H(), MemOperand(x19, 32, PostIndex));
  __ St2(v0.V4S(), v1.V4S(), MemOperand(x19, x22, PostIndex));
  __ St2(v0.V2D(), v1.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1405041312030211, 0x1001000211011000, q0);
  CHECK_EQUAL_128(0x1C0D0C1B1A0B0A19, 0x1809081716070615, q1);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201001F1E0F0E1D, q2);
  CHECK_EQUAL_128(0x0D0C0B0A09081716, 0x1514131211100706, q3);
  CHECK_EQUAL_128(0x4F4E4D4C4B4A1F1E, 0x1D1C1B1A19180F0E, q4);
}

TEST(neon_st3_d) {
  INIT_V8();
  SETUP();

  uint8_t src[3 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x19));
  __ Add(x19, x19, 3);
  __ St3(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x19));
  __ Add(x19, x19, 2);
  __ St3(v0.V2S(), v1.V2S(), v2.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2221201312111003, 0x0201000100201000, q0);
  CHECK_EQUAL_128(0x1F1E1D2726252417, 0x1615140706050423, q1);
}

TEST(neon_st3_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V8B(), v1.V8B(), v2.V8B(), MemOperand(x19, x22, PostIndex));
  __ St3(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x19, 24, PostIndex));
  __ St3(v0.V2S(), v1.V2S(), v2.V2S(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x0201002726171607, 0x0625241514050423, q1);
  CHECK_EQUAL_128(0x1615140706050423, 0x2221201312111003, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736352726252417, q3);
}

TEST(neon_st3_q) {
  INIT_V8();
  SETUP();

  uint8_t src[6 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V16B(), v1.V16B(), v2.V16B(), MemOperand(x19));
  __ Add(x19, x19, 5);
  __ St3(v0.V8H(), v1.V8H(), v2.V8H(), MemOperand(x19));
  __ Add(x19, x19, 12);
  __ St3(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x19));
  __ Add(x19, x19, 22);
  __ St3(v0.V2D(), v1.V2D(), v2.V2D(), MemOperand(x19));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x0605042322212013, 0x1211100302010023, q1);
  CHECK_EQUAL_128(0x1007060504030201, 0x0025241716151407, q2);
  CHECK_EQUAL_128(0x0827262524232221, 0x2017161514131211, q3);
  CHECK_EQUAL_128(0x281F1E1D1C1B1A19, 0x180F0E0D0C0B0A09, q4);
  CHECK_EQUAL_128(0x5F5E5D5C5B5A5958, 0x572F2E2D2C2B2A29, q5);
}

TEST(neon_st3_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[7 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));

  __ St3(v0.V16B(), v1.V16B(), v2.V16B(), MemOperand(x28, x22, PostIndex));
  __ St3(v0.V8H(), v1.V8H(), v2.V8H(), MemOperand(x28, 48, PostIndex));
  __ St3(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x28, x22, PostIndex));
  __ St3(v0.V2D(), v1.V2D(), v2.V2D(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x2213120302212011, 0x1001001101201000, q0);
  CHECK_EQUAL_128(0x1809082726171607, 0x0625241514050423, q1);
  CHECK_EQUAL_128(0x0E2D2C1D1C0D0C2B, 0x2A1B1A0B0A292819, q2);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201002F2E1F1E0F, q3);
  CHECK_EQUAL_128(0x2524232221201716, 0x1514131211100706, q4);
  CHECK_EQUAL_128(0x1D1C1B1A19180F0E, 0x0D0C0B0A09082726, q5);
  CHECK_EQUAL_128(0x6F6E6D6C6B6A2F2E, 0x2D2C2B2A29281F1E, q6);
}

TEST(neon_st4_d) {
  INIT_V8();
  SETUP();

  uint8_t src[4 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), MemOperand(x28));
  __ Add(x28, x28, 12);
  __ St4(v0.V4H(), v1.V4H(), v2.V4H(), v3.V4H(), MemOperand(x28));
  __ Add(x28, x28, 15);
  __ St4(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1110010032221202, 0X3121110130201000, q0);
  CHECK_EQUAL_128(0x1003020100322322, 0X1312030231302120, q1);
  CHECK_EQUAL_128(0x1407060504333231, 0X3023222120131211, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B373635, 0x3427262524171615, q3);
}

TEST(neon_st4_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[5 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V4H(), v1.V4H(), v2.V4H(), v3.V4H(),
         MemOperand(x28, 32, PostIndex));
  __ St4(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x1607063534252415, 0x1405043332232213, q1);
  CHECK_EQUAL_128(0x2221201312111003, 0x0201003736272617, q2);
  CHECK_EQUAL_128(0x2625241716151407, 0x0605043332313023, q3);
  CHECK_EQUAL_128(0x4F4E4D4C4B4A4948, 0x4746453736353427, q4);
}

TEST(neon_st4_q) {
  INIT_V8();
  SETUP();

  uint8_t src[7 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), MemOperand(x28));
  __ Add(x28, x28, 5);
  __ St4(v0.V8H(), v1.V8H(), v2.V8H(), v3.V8H(), MemOperand(x28));
  __ Add(x28, x28, 12);
  __ St4(v0.V4S(), v1.V4S(), v2.V4S(), v3.V4S(), MemOperand(x28));
  __ Add(x28, x28, 22);
  __ St4(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x28));
  __ Add(x28, x28, 10);

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x3231302322212013, 0x1211100302010013, q1);
  CHECK_EQUAL_128(0x1007060504030201, 0x0015140706050433, q2);
  CHECK_EQUAL_128(0x3027262524232221, 0x2017161514131211, q3);
  CHECK_EQUAL_128(0x180F0E0D0C0B0A09, 0x0837363534333231, q4);
  CHECK_EQUAL_128(0x382F2E2D2C2B2A29, 0x281F1E1D1C1B1A19, q5);
  CHECK_EQUAL_128(0x6F6E6D6C6B6A6968, 0x673F3E3D3C3B3A39, q6);
}

TEST(neon_st4_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[9 * 16];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x22, 5);
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St4(v0.V16B(), v1.V16B(), v2.V16B(), v3.V16B(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V8H(), v1.V8H(), v2.V8H(), v3.V8H(),
         MemOperand(x28, 64, PostIndex));
  __ St4(v0.V4S(), v1.V4S(), v2.V4S(), v3.V4S(),
         MemOperand(x28, x22, PostIndex));
  __ St4(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x28));

  __ Mov(x19, src_base);
  __ Ldr(q0, MemOperand(x19, 16, PostIndex));
  __ Ldr(q1, MemOperand(x19, 16, PostIndex));
  __ Ldr(q2, MemOperand(x19, 16, PostIndex));
  __ Ldr(q3, MemOperand(x19, 16, PostIndex));
  __ Ldr(q4, MemOperand(x19, 16, PostIndex));
  __ Ldr(q5, MemOperand(x19, 16, PostIndex));
  __ Ldr(q6, MemOperand(x19, 16, PostIndex));
  __ Ldr(q7, MemOperand(x19, 16, PostIndex));
  __ Ldr(q8, MemOperand(x19, 16, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x1203023130212011, 0x1001000130201000, q0);
  CHECK_EQUAL_128(0x1607063534252415, 0x1405043332232213, q1);
  CHECK_EQUAL_128(0x1A0B0A3938292819, 0x1809083736272617, q2);
  CHECK_EQUAL_128(0x1E0F0E3D3C2D2C1D, 0x1C0D0C3B3A2B2A1B, q3);
  CHECK_EQUAL_128(0x0504030201001003, 0x0201003F3E2F2E1F, q4);
  CHECK_EQUAL_128(0x2524232221201716, 0x1514131211100706, q5);
  CHECK_EQUAL_128(0x0D0C0B0A09083736, 0x3534333231302726, q6);
  CHECK_EQUAL_128(0x2D2C2B2A29281F1E, 0x1D1C1B1A19180F0E, q7);
  CHECK_EQUAL_128(0x8F8E8D8C8B8A3F3E, 0x3D3C3B3A39382F2E, q8);
}

TEST(neon_destructive_minmaxp) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0, 0x2222222233333333);
  __ Movi(v1.V2D(), 0, 0x0000000011111111);

  __ Sminp(v16.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v17, v0);
  __ Sminp(v17.V2S(), v17.V2S(), v1.V2S());
  __ Mov(v18, v1);
  __ Sminp(v18.V2S(), v0.V2S(), v18.V2S());
  __ Mov(v19, v0);
  __ Sminp(v19.V2S(), v19.V2S(), v19.V2S());

  __ Smaxp(v20.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v21, v0);
  __ Smaxp(v21.V2S(), v21.V2S(), v1.V2S());
  __ Mov(v22, v1);
  __ Smaxp(v22.V2S(), v0.V2S(), v22.V2S());
  __ Mov(v23, v0);
  __ Smaxp(v23.V2S(), v23.V2S(), v23.V2S());

  __ Uminp(v24.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v25, v0);
  __ Uminp(v25.V2S(), v25.V2S(), v1.V2S());
  __ Mov(v26, v1);
  __ Uminp(v26.V2S(), v0.V2S(), v26.V2S());
  __ Mov(v27, v0);
  __ Uminp(v27.V2S(), v27.V2S(), v27.V2S());

  __ Umaxp(v28.V2S(), v0.V2S(), v1.V2S());
  __ Mov(v29, v0);
  __ Umaxp(v29.V2S(), v29.V2S(), v1.V2S());
  __ Mov(v30, v1);
  __ Umaxp(v30.V2S(), v0.V2S(), v30.V2S());
  __ Mov(v31, v0);
  __ Umaxp(v31.V2S(), v31.V2S(), v31.V2S());
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0000000022222222, q16);
  CHECK_EQUAL_128(0, 0x0000000022222222, q17);
  CHECK_EQUAL_128(0, 0x0000000022222222, q18);
  CHECK_EQUAL_128(0, 0x2222222222222222, q19);

  CHECK_EQUAL_128(0, 0x1111111133333333, q20);
  CHECK_EQUAL_128(0, 0x1111111133333333, q21);
  CHECK_EQUAL_128(0, 0x1111111133333333, q22);
  CHECK_EQUAL_128(0, 0x3333333333333333, q23);

  CHECK_EQUAL_128(0, 0x0000000022222222, q24);
  CHECK_EQUAL_128(0, 0x0000000022222222, q25);
  CHECK_EQUAL_128(0, 0x0000000022222222, q26);
  CHECK_EQUAL_128(0, 0x2222222222222222, q27);

  CHECK_EQUAL_128(0, 0x1111111133333333, q28);
  CHECK_EQUAL_128(0, 0x1111111133333333, q29);
  CHECK_EQUAL_128(0, 0x1111111133333333, q30);
  CHECK_EQUAL_128(0, 0x3333333333333333, q31);
}

TEST(neon_destructive_tbl) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x0041424334353627, 0x28291A1B1C0D0E0F);
  __ Movi(v1.V2D(), 0xAFAEADACABAAA9A8, 0xA7A6A5A4A3A2A1A0);
  __ Movi(v2.V2D(), 0xBFBEBDBCBBBAB9B8, 0xB7B6B5B4B3B2B1B0);
  __ Movi(v3.V2D(), 0xCFCECDCCCBCAC9C8, 0xC7C6C5C4C3C2C1C0);
  __ Movi(v4.V2D(), 0xDFDEDDDCDBDAD9D8, 0xD7D6D5D4D3D2D1D0);

  __ Movi(v16.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbl(v16.V16B(), v1.V16B(), v0.V16B());
  __ Mov(v17, v0);
  __ Tbl(v17.V16B(), v1.V16B(), v17.V16B());
  __ Mov(v18, v1);
  __ Tbl(v18.V16B(), v18.V16B(), v0.V16B());
  __ Mov(v19, v0);
  __ Tbl(v19.V16B(), v19.V16B(), v19.V16B());

  __ Movi(v20.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbl(v20.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v0.V16B());
  __ Mov(v21, v0);
  __ Tbl(v21.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v21.V16B());
  __ Mov(v22, v1);
  __ Mov(v23, v2);
  __ Mov(v24, v3);
  __ Mov(v25, v4);
  __ Tbl(v22.V16B(), v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(), v0.V16B());
  __ Mov(v26, v0);
  __ Mov(v27, v1);
  __ Mov(v28, v2);
  __ Mov(v29, v3);
  __ Tbl(v26.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B(),
         v26.V16B());
  END();

  RUN();

  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q16);
  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q17);
  CHECK_EQUAL_128(0xA000000000000000, 0x0000000000ADAEAF, q18);
  CHECK_EQUAL_128(0x0F00000000000000, 0x0000000000424100, q19);

  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q20);
  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q21);
  CHECK_EQUAL_128(0xA0000000D4D5D6C7, 0xC8C9BABBBCADAEAF, q22);
  CHECK_EQUAL_128(0x0F000000C4C5C6B7, 0xB8B9AAABAC424100, q26);
}

TEST(neon_destructive_tbx) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x0041424334353627, 0x28291A1B1C0D0E0F);
  __ Movi(v1.V2D(), 0xAFAEADACABAAA9A8, 0xA7A6A5A4A3A2A1A0);
  __ Movi(v2.V2D(), 0xBFBEBDBCBBBAB9B8, 0xB7B6B5B4B3B2B1B0);
  __ Movi(v3.V2D(), 0xCFCECDCCCBCAC9C8, 0xC7C6C5C4C3C2C1C0);
  __ Movi(v4.V2D(), 0xDFDEDDDCDBDAD9D8, 0xD7D6D5D4D3D2D1D0);

  __ Movi(v16.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbx(v16.V16B(), v1.V16B(), v0.V16B());
  __ Mov(v17, v0);
  __ Tbx(v17.V16B(), v1.V16B(), v17.V16B());
  __ Mov(v18, v1);
  __ Tbx(v18.V16B(), v18.V16B(), v0.V16B());
  __ Mov(v19, v0);
  __ Tbx(v19.V16B(), v19.V16B(), v19.V16B());

  __ Movi(v20.V2D(), 0x5555555555555555, 0x5555555555555555);
  __ Tbx(v20.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v0.V16B());
  __ Mov(v21, v0);
  __ Tbx(v21.V16B(), v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), v21.V16B());
  __ Mov(v22, v1);
  __ Mov(v23, v2);
  __ Mov(v24, v3);
  __ Mov(v25, v4);
  __ Tbx(v22.V16B(), v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(), v0.V16B());
  __ Mov(v26, v0);
  __ Mov(v27, v1);
  __ Mov(v28, v2);
  __ Mov(v29, v3);
  __ Tbx(v26.V16B(), v26.V16B(), v27.V16B(), v28.V16B(), v29.V16B(),
         v26.V16B());
  END();

  RUN();

  CHECK_EQUAL_128(0xA055555555555555, 0x5555555555ADAEAF, q16);
  CHECK_EQUAL_128(0xA041424334353627, 0x28291A1B1CADAEAF, q17);
  CHECK_EQUAL_128(0xA0AEADACABAAA9A8, 0xA7A6A5A4A3ADAEAF, q18);
  CHECK_EQUAL_128(0x0F41424334353627, 0x28291A1B1C424100, q19);

  CHECK_EQUAL_128(0xA0555555D4D5D6C7, 0xC8C9BABBBCADAEAF, q20);
  CHECK_EQUAL_128(0xA0414243D4D5D6C7, 0xC8C9BABBBCADAEAF, q21);
  CHECK_EQUAL_128(0xA0AEADACD4D5D6C7, 0xC8C9BABBBCADAEAF, q22);
  CHECK_EQUAL_128(0x0F414243C4C5C6B7, 0xB8B9AAABAC424100, q26);
}

TEST(neon_destructive_fcvtl) {
  INIT_V8();
  SETUP();

  START();
  __ Movi(v0.V2D(), 0x400000003F800000, 0xBF800000C0000000);
  __ Fcvtl(v16.V2D(), v0.V2S());
  __ Fcvtl2(v17.V2D(), v0.V4S());
  __ Mov(v18, v0);
  __ Mov(v19, v0);
  __ Fcvtl(v18.V2D(), v18.V2S());
  __ Fcvtl2(v19.V2D(), v19.V4S());

  __ Movi(v1.V2D(), 0x40003C003C004000, 0xC000BC00BC00C000);
  __ Fcvtl(v20.V4S(), v1.V4H());
  __ Fcvtl2(v21.V4S(), v1.V8H());
  __ Mov(v22, v1);
  __ Mov(v23, v1);
  __ Fcvtl(v22.V4S(), v22.V4H());
  __ Fcvtl2(v23.V4S(), v23.V8H());

  END();

  RUN();

  CHECK_EQUAL_128(0xBFF0000000000000, 0xC000000000000000, q16);
  CHECK_EQUAL_128(0x4000000000000000, 0x3FF0000000000000, q17);
  CHECK_EQUAL_128(0xBFF0000000000000, 0xC000000000000000, q18);
  CHECK_EQUAL_128(0x4000000000000000, 0x3FF0000000000000, q19);

  CHECK_EQUAL_128(0xC0000000BF800000, 0xBF800000C0000000, q20);
  CHECK_EQUAL_128(0x400000003F800000, 0x3F80000040000000, q21);
  CHECK_EQUAL_128(0xC0000000BF800000, 0xBF800000C0000000, q22);
  CHECK_EQUAL_128(0x400000003F800000, 0x3F80000040000000, q23);
}

TEST(ldp_stp_float) {
  INIT_V8();
  SETUP();

  float src[2] = {1.0, 2.0};
  float dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(s31, s0, MemOperand(x16, 2 * sizeof(src[0]), PostIndex));
  __ Stp(s0, s31, MemOperand(x17, sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_FP32(1.0, s31);
  CHECK_EQUAL_FP32(2.0, s0);
  CHECK_EQUAL_FP32(0.0, dst[0]);
  CHECK_EQUAL_FP32(2.0, dst[1]);
  CHECK_EQUAL_FP32(1.0, dst[2]);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + sizeof(dst[1]), x17);
}

TEST(ldp_stp_double) {
  INIT_V8();
  SETUP();

  double src[2] = {1.0, 2.0};
  double dst[3] = {0.0, 0.0, 0.0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(d31, d0, MemOperand(x16, 2 * sizeof(src[0]), PostIndex));
  __ Stp(d0, d31, MemOperand(x17, sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_FP64(1.0, d31);
  CHECK_EQUAL_FP64(2.0, d0);
  CHECK_EQUAL_FP64(0.0, dst[0]);
  CHECK_EQUAL_FP64(2.0, dst[1]);
  CHECK_EQUAL_FP64(1.0, dst[2]);
  CHECK_EQUAL_64(src_base + 2 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + sizeof(dst[1]), x17);
}

TEST(ldp_stp_quad) {
  SETUP();

  uint64_t src[4] = {0x0123456789ABCDEF, 0xAAAAAAAA55555555, 0xFEDCBA9876543210,
                     0x55555555AAAAAAAA};
  uint64_t dst[6] = {0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Ldp(q31, q0, MemOperand(x16, 4 * sizeof(src[0]), PostIndex));
  __ Stp(q0, q31, MemOperand(x17, 2 * sizeof(dst[1]), PreIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0xAAAAAAAA55555555, 0x0123456789ABCDEF, q31);
  CHECK_EQUAL_128(0x55555555AAAAAAAA, 0xFEDCBA9876543210, q0);
  CHECK_EQUAL_64(0, dst[0]);
  CHECK_EQUAL_64(0, dst[1]);
  CHECK_EQUAL_64(0xFEDCBA9876543210, dst[2]);
  CHECK_EQUAL_64(0x55555555AAAAAAAA, dst[3]);
  CHECK_EQUAL_64(0x0123456789ABCDEF, dst[4]);
  CHECK_EQUAL_64(0xAAAAAAAA55555555, dst[5]);
  CHECK_EQUAL_64(src_base + 4 * sizeof(src[0]), x16);
  CHECK_EQUAL_64(dst_base + 2 * sizeof(dst[1]), x17);
}

TEST(ldp_stp_offset) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL};
  uint64_t dst[7] = {0, 0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, src_base + 24);
  __ Mov(x19, dst_base + 56);
  __ Ldp(w0, w1, MemOperand(x16));
  __ Ldp(w2, w3, MemOperand(x16, 4));
  __ Ldp(x4, x5, MemOperand(x16, 8));
  __ Ldp(w6, w7, MemOperand(x28, -12));
  __ Ldp(x8, x9, MemOperand(x28, -16));
  __ Stp(w0, w1, MemOperand(x17));
  __ Stp(w2, w3, MemOperand(x17, 8));
  __ Stp(x4, x5, MemOperand(x17, 16));
  __ Stp(w6, w7, MemOperand(x19, -24));
  __ Stp(x8, x9, MemOperand(x19, -16));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[0]);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[2]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[3]);
  CHECK_EQUAL_64(0x8899AABB, x6);
  CHECK_EQUAL_64(0xBBAA9988, x7);
  CHECK_EQUAL_64(0xBBAA99888899AABBUL, dst[4]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x8);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[5]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x9);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[6]);
  CHECK_EQUAL_64(src_base, x16);
  CHECK_EQUAL_64(dst_base, x17);
  CHECK_EQUAL_64(src_base + 24, x28);
  CHECK_EQUAL_64(dst_base + 56, x19);
}

TEST(ldp_stp_offset_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677, 0x8899AABBCCDDEEFF,
                     0xFFEEDDCCBBAA9988};
  uint64_t dst[7] = {0, 0, 0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x20, src_base - base_offset);
  __ Mov(x21, dst_base - base_offset);
  __ Mov(x28, src_base + base_offset + 24);
  __ Mov(x19, dst_base + base_offset + 56);
  __ Ldp(w0, w1, MemOperand(x20, base_offset));
  __ Ldp(w2, w3, MemOperand(x20, base_offset + 4));
  __ Ldp(x4, x5, MemOperand(x20, base_offset + 8));
  __ Ldp(w6, w7, MemOperand(x28, -12 - base_offset));
  __ Ldp(x8, x9, MemOperand(x28, -16 - base_offset));
  __ Stp(w0, w1, MemOperand(x21, base_offset));
  __ Stp(w2, w3, MemOperand(x21, base_offset + 8));
  __ Stp(x4, x5, MemOperand(x21, base_offset + 16));
  __ Stp(w6, w7, MemOperand(x19, -24 - base_offset));
  __ Stp(x8, x9, MemOperand(x19, -16 - base_offset));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[0]);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[2]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[3]);
  CHECK_EQUAL_64(0x8899AABB, x6);
  CHECK_EQUAL_64(0xBBAA9988, x7);
  CHECK_EQUAL_64(0xBBAA99888899AABBUL, dst[4]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x8);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[5]);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x9);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[6]);
  CHECK_EQUAL_64(src_base - base_offset, x20);
  CHECK_EQUAL_64(dst_base - base_offset, x21);
  CHECK_EQUAL_64(src_base + base_offset + 24, x28);
  CHECK_EQUAL_64(dst_base + base_offset + 56, x19);
}

TEST(ldp_stp_preindex) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x16, 4, PreIndex));
  __ Mov(x19, x16);
  __ Ldp(w2, w3, MemOperand(x16, -4, PreIndex));
  __ Stp(w2, w3, MemOperand(x17, 4, PreIndex));
  __ Mov(x20, x17);
  __ Stp(w0, w1, MemOperand(x17, -4, PreIndex));
  __ Ldp(x4, x5, MemOperand(x16, 8, PreIndex));
  __ Mov(x21, x16);
  __ Ldp(x6, x7, MemOperand(x16, -8, PreIndex));
  __ Stp(x7, x6, MemOperand(x28, 8, PreIndex));
  __ Mov(x22, x28);
  __ Stp(x5, x4, MemOperand(x28, -8, PreIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x00112233, x0);
  CHECK_EQUAL_64(0xCCDDEEFF, x1);
  CHECK_EQUAL_64(0x44556677, x2);
  CHECK_EQUAL_64(0x00112233, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0x0011223344556677UL, x6);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base, x16);
  CHECK_EQUAL_64(dst_base, x17);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 4, x19);
  CHECK_EQUAL_64(dst_base + 4, x20);
  CHECK_EQUAL_64(src_base + 8, x21);
  CHECK_EQUAL_64(dst_base + 24, x22);
}

TEST(ldp_stp_preindex_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[3] = {0x0011223344556677, 0x8899AABBCCDDEEFF,
                     0xFFEEDDCCBBAA9988};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x24, src_base - base_offset);
  __ Mov(x25, dst_base + base_offset);
  __ Mov(x28, dst_base + base_offset + 16);
  __ Ldp(w0, w1, MemOperand(x24, base_offset + 4, PreIndex));
  __ Mov(x19, x24);
  __ Mov(x24, src_base - base_offset + 4);
  __ Ldp(w2, w3, MemOperand(x24, base_offset - 4, PreIndex));
  __ Stp(w2, w3, MemOperand(x25, 4 - base_offset, PreIndex));
  __ Mov(x20, x25);
  __ Mov(x25, dst_base + base_offset + 4);
  __ Mov(x24, src_base - base_offset);
  __ Stp(w0, w1, MemOperand(x25, -4 - base_offset, PreIndex));
  __ Ldp(x4, x5, MemOperand(x24, base_offset + 8, PreIndex));
  __ Mov(x21, x24);
  __ Mov(x24, src_base - base_offset + 8);
  __ Ldp(x6, x7, MemOperand(x24, base_offset - 8, PreIndex));
  __ Stp(x7, x6, MemOperand(x28, 8 - base_offset, PreIndex));
  __ Mov(x22, x28);
  __ Mov(x28, dst_base + base_offset + 16 + 8);
  __ Stp(x5, x4, MemOperand(x28, -8 - base_offset, PreIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x00112233, x0);
  CHECK_EQUAL_64(0xCCDDEEFF, x1);
  CHECK_EQUAL_64(0x44556677, x2);
  CHECK_EQUAL_64(0x00112233, x3);
  CHECK_EQUAL_64(0xCCDDEEFF00112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x4);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x5);
  CHECK_EQUAL_64(0x0011223344556677UL, x6);
  CHECK_EQUAL_64(0x889
```