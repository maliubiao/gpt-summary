Response:
The user is asking for a functional summary of the provided C++ code snippet, which is part of the V8 JavaScript engine's testing framework. The code focuses on testing the ARM64 assembler, specifically the NEON (Advanced SIMD) instructions related to loading and storing multiple elements from memory.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The code uses `TEST()` macros, which clearly indicates it's a test file. The names of the tests, like `neon_ld4_lane`, `neon_st2_lane`, and `neon_ld1_alllanes`, strongly suggest it's testing NEON load and store instructions. The `arm64` in the filename confirms the target architecture.

2. **Analyze Test Structure:** Each `TEST()` function generally follows a pattern:
    * `INIT_V8()`: Initializes the V8 environment for the test.
    * `SETUP()`: Sets up any necessary data structures. Here, it usually involves creating a `src` array of bytes and getting its address.
    * `START()`: Marks the beginning of the code to be assembled.
    * A series of `__` prefixed instructions: These are the ARM64 assembler instructions being tested. Instructions like `Ld4`, `St2`, `Ldr`, `Mov`, `Add`, `Ld4r` are common.
    * `END()`: Marks the end of the assembled code.
    * `RUN()`: Executes the assembled code.
    * A series of `CHECK_EQUAL_*` macros:  These verify the results of the instructions by comparing the contents of registers with expected values.
    * Optionally, checks on the final value of memory pointers modified using post-indexing.

3. **Categorize the Tests:** Group the tests based on the NEON instruction being tested:
    * `ld4`: Load four registers from memory. There are variations for loading by lane (individual elements) and all lanes (entire registers at once), and for using post-indexing (incrementing the memory pointer after the load).
    * `st1`, `st2`, `st3`, `st4`: Store one, two, three, or four registers to memory. Similar variations exist for lane access and post-indexing.
    * `ld1`: Load one register from memory. Again, with lane and all-lane variations and post-indexing.

4. **Identify Key Concepts:**
    * **NEON/SIMD:**  The code deals with Single Instruction, Multiple Data operations, which are crucial for performance in multimedia and other data-parallel tasks.
    * **Load/Store Instructions:** These instructions move data between memory and registers.
    * **Lane Access:**  The ability to load or store individual elements (lanes) within a NEON register.
    * **All Lanes Access:** Loading or storing the entire contents of NEON registers.
    * **Post-Indexing:** A memory addressing mode where the memory address is updated (incremented) after the memory access. This is efficient for iterating through memory.
    * **Registers:**  The code manipulates NEON registers (e.g., `v0`, `v1`, `q0`, `q1`) and general-purpose registers (e.g., `x17`, `x19`).
    * **Memory Operands:**  The `MemOperand` construct specifies the memory address to access.

5. **Determine if it's Torque:** The prompt explicitly asks if the file ends with `.tq`. Since the given file ends with `.cc`, it is a C++ file, *not* a Torque file.

6. **Relate to JavaScript (if applicable):** While this C++ code directly tests the assembler, NEON instructions are used to optimize JavaScript execution in V8. Think about common JavaScript operations that could benefit from SIMD:
    * Array manipulation (e.g., adding numbers in two arrays).
    * Image processing.
    * Audio processing.
    * Mathematical calculations on large datasets.

7. **Infer Code Logic and I/O:** The `CHECK_EQUAL_*` macros provide the expected outputs for specific input conditions. The `src` array is the primary input data. The registers are the outputs being verified. For example, in `neon_ld4_lane`, the code loads data from the `src` array into registers `q0` through `q3`, and the `CHECK_EQUAL_128` lines show what values are expected in those registers. Post-indexing modifies the base address registers (like `x17`).

8. **Consider Common Programming Errors:**  Think about errors developers might make when working with SIMD or memory access:
    * **Incorrect Memory Alignment:** NEON instructions often have alignment requirements.
    * **Out-of-Bounds Access:**  Reading or writing beyond the allocated memory.
    * **Incorrect Register Usage:** Using the wrong register or an uninitialized register.
    * **Off-by-One Errors:** Mistakes in loop bounds or pointer arithmetic.

9. **Synthesize the Summary:** Combine the observations into a concise summary, addressing all the points in the user's request.

By following these steps, one can analyze the provided code snippet and produce the detailed functional summary provided in the initial good answer.
```cpp
TEST(neon_ld1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Mov(x19, src_base);
  __ Mov(x20, src_base);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);

  // Test loading whole register by element.
  for (int i = 15; i >= 0; i--) {
    __ Ld1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld1(v1.H(), i, MemOperand(x28, 2, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld1(v2.S(), i, MemOperand(x19, 4, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld1(v3.D(), i, MemOperand(x20, 8, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Ldr(q4, MemOperand(x21));
  __ Ld1(v4.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q5, MemOperand(x22));
  __ Ld1(v5.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q6, MemOperand(x23));
  __ Ld1(v6.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q7, MemOperand(x24));
  __ Ld1(v7.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q1);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q2);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q3);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q4);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q5);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q6);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q7);
  CHECK_EQUAL_64(src_base + 16, x17);
  CHECK_EQUAL_64(src_base + 16, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(src_base + 16, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_st1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, -16);
  __ Ldr(q0, MemOperand(x17));

  for (int i = 15; i >= 0; i--) {
    __ St1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }
  __ Ldr(q1, MemOperand(x17, x19));

  for (int i = 7; i >= 0; i--) {
    __ St1(v0.H(), i, MemOperand(x17, 2, PostIndex));
  }
  __ Ldr(q2, MemOperand(x17, x19));

  for (int i = 3; i >= 0; i--) {
    __ St1(v0.S(), i, MemOperand(x17, 4, PostIndex));
  }
  __ Ldr(q3, MemOperand(x17, x19));

  for (int i = 1; i >= 0; i--) {
    __ St1(v0.D(), i, MemOperand(x17, 8, PostIndex));
  }
  __ Ldr(q4, MemOperand(x17, x19));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q1);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q2);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q3);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q4);
}

TEST(neon_ld1_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld1r(v0.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v1.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v2.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v3.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v4.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v5.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v6.V1D(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v7.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0807060508070605, q4);
  CHECK_EQUAL_128(0x0908070609080706, 0x0908070609080706, q5);
  CHECK_EQUAL_128(0, 0x0E0D0C0B0A090807, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0F0E0D0C0B0A0908, q7);
}

TEST(neon_ld1_alllanes_postindex) {
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
  __ Ld1r(v0.V8B(), MemOperand(x17, 1, PostIndex));
  __ Ld1r(v1.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v2.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v3.V8H(), MemOperand(x17, 2, PostIndex));
  __ Ld1r(v4.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v5.V4S(), MemOperand(x17, 4, PostIndex));
  __ Ld1r(v6.V2D(), MemOperand(x17, 8, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0908070609080706, q4);
  CHECK_EQUAL_128(0x0A0908070A090807, 0x0A0908070A090807, q5);
  CHECK_EQUAL_128(0x1211100F0E0D0C0B, 0x1211100F0E0D0C0B, q6);
  CHECK_EQUAL_64(src_base + 19, x17);
}

TEST(neon_st1_d) {
  INIT_V8();
  SETUP();

  uint8_t src[14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17));
  __ Ldr(d16, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17));
  __ Ldr(d18, MemOperand(x17, 8, PostIndex));
  __ Ldr(d19, MemOperand(x17, 8, PostIndex));
  __ Ldr(d20, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x17));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(), MemOperand(x17));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q0);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q1);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q3);
  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -8);
  __ Mov(x19, -16);
  __ Mov(x20, -24);
  __ Mov(x21, -32);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17, 8, PostIndex));
  __ Ldr(d16, MemOperand(x17, x28));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17, 16, PostIndex));
  __ Ldr(q17, MemOperand(x17, x19));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17, 24, PostIndex));
  __ Ldr(d18, MemOperand(x17, x20));
  __ Ldr(d19, MemOperand(x17, x19));
  __ Ldr(d20, MemOperand(x17, x28));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q21, MemOperand(x17, x21));
  __ Ldr(q22, MemOperand(x17, x19));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q23, MemOperand(x17, x21));
  __ Ldr(q24, MemOperand(x17, x19));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17));
  __ Ldr(q16, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V8H(), v1.V8H(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));
  __ Ldr(q18, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x17));
  __ Ldr(q19, MemOperand(x17, 16, PostIndex));
  __ Ldr(q20, MemOperand(x17, 16, PostIndex));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x17));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17, 16, PostIndex));
  __ Ldr(q25, MemOperand(x17));
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

TEST(neon_st1_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -16);
```

好的，这是第5部分的代码。让我们来归纳一下它的功能。

**功能归纳:**

这段代码是V8 JavaScript引擎中用于测试ARM64汇编器的代码片段，专门针对NEON（Advanced SIMD）指令的存储 (store) 操作进行测试。它测试了 `ST1` 指令的不同变体，用于将一个NEON寄存器的内容存储到内存中。

**具体功能点:**

1. **`TEST(neon_ld1_lane_postindex)` 和 `TEST(neon_st1_lane_postindex)`:**  这两个测试配对出现，尽管当前代码片段只包含了 `neon_st1_lane_postindex`。它们分别测试了从内存加载 (`LD1`) 和向内存存储 (`ST1`) 单个NEON寄存器
Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共15部分，请归纳一下它的功能

"""
1F1E1D1C1B1A1918, 0x0302151413121110, q21);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q22);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x0706353433323130, q23);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q24);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q25);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q26);
  CHECK_EQUAL_128(0x3F3E3D3C0F0E0D0C, 0x3736353433323130, q27);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q28);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q29);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q30);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3736353433323130, q31);
}

TEST(neon_ld4_lane_postindex) {
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
    __ Ld4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x17, 4, PostIndex));
  }

  __ Mov(x28, src_base);
  for (int i = 7; i >= 0; i--) {
    __ Ld4(v4.H(), v5.H(), v6.H(), v7.H(), i, MemOperand(x28, 8, PostIndex));
  }

  __ Mov(x19, src_base);
  for (int i = 3; i >= 0; i--) {
    __ Ld4(v8_.S(), v9.S(), v10.S(), v11.S(), i,
           MemOperand(x19, 16, PostIndex));
  }

  __ Mov(x20, src_base);
  for (int i = 1; i >= 0; i--) {
    __ Ld4(v12.D(), v13.D(), v14.D(), v15.D(), i,
           MemOperand(x20, 32, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);

  __ Mov(x4, x21);
  __ Ldr(q16, MemOperand(x4, 16, PostIndex));
  __ Ldr(q17, MemOperand(x4, 16, PostIndex));
  __ Ldr(q18, MemOperand(x4, 16, PostIndex));
  __ Ldr(q19, MemOperand(x4));
  __ Ld4(v16.B(), v17.B(), v18.B(), v19.B(), 4,
         MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x5, x22);
  __ Ldr(q20, MemOperand(x5, 16, PostIndex));
  __ Ldr(q21, MemOperand(x5, 16, PostIndex));
  __ Ldr(q22, MemOperand(x5, 16, PostIndex));
  __ Ldr(q23, MemOperand(x5));
  __ Ld4(v20.H(), v21.H(), v22.H(), v23.H(), 3,
         MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x6, x23);
  __ Ldr(q24, MemOperand(x6, 16, PostIndex));
  __ Ldr(q25, MemOperand(x6, 16, PostIndex));
  __ Ldr(q26, MemOperand(x6, 16, PostIndex));
  __ Ldr(q27, MemOperand(x6));
  __ Ld4(v24.S(), v25.S(), v26.S(), v27.S(), 2,
         MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Mov(x7, x24);
  __ Ldr(q28, MemOperand(x7, 16, PostIndex));
  __ Ldr(q29, MemOperand(x7, 16, PostIndex));
  __ Ldr(q30, MemOperand(x7, 16, PostIndex));
  __ Ldr(q31, MemOperand(x7));
  __ Ld4(v28.D(), v29.D(), v30.D(), v31.D(), 1,
         MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x0004080C1014181C, 0x2024282C3034383C, q0);
  CHECK_EQUAL_128(0x0105090D1115191D, 0x2125292D3135393D, q1);
  CHECK_EQUAL_128(0x02060A0E12161A1E, 0x22262A2E32363A3E, q2);
  CHECK_EQUAL_128(0x03070B0F13171B1F, 0x23272B2F33373B3F, q3);
  CHECK_EQUAL_128(0x0100090811101918, 0x2120292831303938, q4);
  CHECK_EQUAL_128(0x03020B0A13121B1A, 0x23222B2A33323B3A, q5);
  CHECK_EQUAL_128(0x05040D0C15141D1C, 0x25242D2C35343D3C, q6);
  CHECK_EQUAL_128(0x07060F0E17161F1E, 0x27262F2E37363F3E, q7);
  CHECK_EQUAL_128(0x0302010013121110, 0x2322212033323130, q8);
  CHECK_EQUAL_128(0x0706050417161514, 0x2726252437363534, q9);
  CHECK_EQUAL_128(0x0B0A09081B1A1918, 0x2B2A29283B3A3938, q10);
  CHECK_EQUAL_128(0x0F0E0D0C1F1E1D1C, 0x2F2E2D2C3F3E3D3C, q11);
  CHECK_EQUAL_128(0x0706050403020100, 0x2726252423222120, q12);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x2F2E2D2C2B2A2928, q13);
  CHECK_EQUAL_128(0x1716151413121110, 0x3736353433323130, q14);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3F3E3D3C3B3A3938, q15);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q16);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716150113121110, q17);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726250223222120, q18);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736350333323130, q19);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q20);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x0302151413121110, q21);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x0504252423222120, q22);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x0706353433323130, q23);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q24);
  CHECK_EQUAL_128(0x1F1E1D1C07060504, 0x1716151413121110, q25);
  CHECK_EQUAL_128(0x2F2E2D2C0B0A0908, 0x2726252423222120, q26);
  CHECK_EQUAL_128(0x3F3E3D3C0F0E0D0C, 0x3736353433323130, q27);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q28);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x1716151413121110, q29);
  CHECK_EQUAL_128(0x1716151413121110, 0x2726252423222120, q30);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x3736353433323130, q31);

  CHECK_EQUAL_64(src_base + 64, x17);
  CHECK_EQUAL_64(src_base + 64, x28);
  CHECK_EQUAL_64(src_base + 64, x19);
  CHECK_EQUAL_64(src_base + 64, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_ld4_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld4r(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), MemOperand(x17));
  __ Add(x17, x17, 4);
  __ Ld4r(v4.V16B(), v5.V16B(), v6.V16B(), v7.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v8_.V4H(), v9.V4H(), v10.V4H(), v11.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v12.V8H(), v13.V8H(), v14.V8H(), v15.V8H(), MemOperand(x17));
  __ Add(x17, x17, 8);
  __ Ld4r(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld4r(v20.V4S(), v21.V4S(), v22.V4S(), v23.V4S(), MemOperand(x17));
  __ Add(x17, x17, 16);
  __ Ld4r(v24.V2D(), v25.V2D(), v26.V2D(), v27.V2D(), MemOperand(x17));

  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0000000000000000, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0707070707070707, 0x0707070707070707, q6);
  CHECK_EQUAL_128(0x0808080808080808, 0x0808080808080808, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x0908090809080908, q9);
  CHECK_EQUAL_128(0x0000000000000000, 0x0B0A0B0A0B0A0B0A, q10);
  CHECK_EQUAL_128(0x0000000000000000, 0x0D0C0D0C0D0C0D0C, q11);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q12);
  CHECK_EQUAL_128(0x0A090A090A090A09, 0x0A090A090A090A09, q13);
  CHECK_EQUAL_128(0x0C0B0C0B0C0B0C0B, 0x0C0B0C0B0C0B0C0B, q14);
  CHECK_EQUAL_128(0x0E0D0E0D0E0D0E0D, 0x0E0D0E0D0E0D0E0D, q15);
  CHECK_EQUAL_128(0x0000000000000000, 0x1211100F1211100F, q16);
  CHECK_EQUAL_128(0x0000000000000000, 0x1615141316151413, q17);
  CHECK_EQUAL_128(0x0000000000000000, 0x1A1918171A191817, q18);
  CHECK_EQUAL_128(0x0000000000000000, 0x1E1D1C1B1E1D1C1B, q19);
  CHECK_EQUAL_128(0x1312111013121110, 0x1312111013121110, q20);
  CHECK_EQUAL_128(0x1716151417161514, 0x1716151417161514, q21);
  CHECK_EQUAL_128(0x1B1A19181B1A1918, 0x1B1A19181B1A1918, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1F1E1D1C, 0x1F1E1D1C1F1E1D1C, q23);
  CHECK_EQUAL_128(0x2726252423222120, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2F2E2D2C2B2A2928, q25);
  CHECK_EQUAL_128(0x3736353433323130, 0x3736353433323130, q26);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3F3E3D3C3B3A3938, q27);
}

TEST(neon_ld4_alllanes_postindex) {
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
  __ Ld4r(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(),
          MemOperand(x17, 4, PostIndex));
  __ Ld4r(v4.V16B(), v5.V16B(), v6.V16B(), v7.V16B(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v8_.V4H(), v9.V4H(), v10.V4H(), v11.V4H(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v12.V8H(), v13.V8H(), v14.V8H(), v15.V8H(),
          MemOperand(x17, 8, PostIndex));
  __ Ld4r(v16.V2S(), v17.V2S(), v18.V2S(), v19.V2S(),
          MemOperand(x17, x19, PostIndex));
  __ Ld4r(v20.V4S(), v21.V4S(), v22.V4S(), v23.V4S(),
          MemOperand(x17, 16, PostIndex));
  __ Ld4r(v24.V2D(), v25.V2D(), v26.V2D(), v27.V2D(),
          MemOperand(x17, 32, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0x0000000000000000, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0000000000000000, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0x0000000000000000, 0x0303030303030303, q2);
  CHECK_EQUAL_128(0x0000000000000000, 0x0404040404040404, q3);
  CHECK_EQUAL_128(0x0505050505050505, 0x0505050505050505, q4);
  CHECK_EQUAL_128(0x0606060606060606, 0x0606060606060606, q5);
  CHECK_EQUAL_128(0x0707070707070707, 0x0707070707070707, q6);
  CHECK_EQUAL_128(0x0808080808080808, 0x0808080808080808, q7);
  CHECK_EQUAL_128(0x0000000000000000, 0x0706070607060706, q8);
  CHECK_EQUAL_128(0x0000000000000000, 0x0908090809080908, q9);
  CHECK_EQUAL_128(0x0000000000000000, 0x0B0A0B0A0B0A0B0A, q10);
  CHECK_EQUAL_128(0x0000000000000000, 0x0D0C0D0C0D0C0D0C, q11);
  CHECK_EQUAL_128(0x0807080708070807, 0x0807080708070807, q12);
  CHECK_EQUAL_128(0x0A090A090A090A09, 0x0A090A090A090A09, q13);
  CHECK_EQUAL_128(0x0C0B0C0B0C0B0C0B, 0x0C0B0C0B0C0B0C0B, q14);
  CHECK_EQUAL_128(0x0E0D0E0D0E0D0E0D, 0x0E0D0E0D0E0D0E0D, q15);
  CHECK_EQUAL_128(0x0000000000000000, 0x1211100F1211100F, q16);
  CHECK_EQUAL_128(0x0000000000000000, 0x1615141316151413, q17);
  CHECK_EQUAL_128(0x0000000000000000, 0x1A1918171A191817, q18);
  CHECK_EQUAL_128(0x0000000000000000, 0x1E1D1C1B1E1D1C1B, q19);
  CHECK_EQUAL_128(0x1312111013121110, 0x1312111013121110, q20);
  CHECK_EQUAL_128(0x1716151417161514, 0x1716151417161514, q21);
  CHECK_EQUAL_128(0x1B1A19181B1A1918, 0x1B1A19181B1A1918, q22);
  CHECK_EQUAL_128(0x1F1E1D1C1F1E1D1C, 0x1F1E1D1C1F1E1D1C, q23);
  CHECK_EQUAL_128(0x2726252423222120, 0x2726252423222120, q24);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2F2E2D2C2B2A2928, q25);
  CHECK_EQUAL_128(0x3736353433323130, 0x3736353433323130, q26);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3F3E3D3C3B3A3938, q27);
  CHECK_EQUAL_64(src_base + 64, x17);
}

TEST(neon_st1_lane) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, -16);
  __ Ldr(q0, MemOperand(x17));

  for (int i = 15; i >= 0; i--) {
    __ St1(v0.B(), i, MemOperand(x17));
    __ Add(x17, x17, 1);
  }
  __ Ldr(q1, MemOperand(x17, x19));

  for (int i = 7; i >= 0; i--) {
    __ St1(v0.H(), i, MemOperand(x17));
    __ Add(x17, x17, 2);
  }
  __ Ldr(q2, MemOperand(x17, x19));

  for (int i = 3; i >= 0; i--) {
    __ St1(v0.S(), i, MemOperand(x17));
    __ Add(x17, x17, 4);
  }
  __ Ldr(q3, MemOperand(x17, x19));

  for (int i = 1; i >= 0; i--) {
    __ St1(v0.D(), i, MemOperand(x17));
    __ Add(x17, x17, 8);
  }
  __ Ldr(q4, MemOperand(x17, x19));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q1);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q2);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q3);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q4);
}

TEST(neon_st2_lane) {
  INIT_V8();
  SETUP();

  // Struct size * addressing modes * element sizes * vector size.
  uint8_t dst[2 * 2 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);

  // Test B stores with and without post index.
  for (int i = 15; i >= 0; i--) {
    __ St2(v0.B(), v1.B(), i, MemOperand(x19));
    __ Add(x19, x19, 2);
  }
  for (int i = 15; i >= 0; i--) {
    __ St2(v0.B(), v1.B(), i, MemOperand(x19, 2, PostIndex));
  }
  __ Ldr(q2, MemOperand(x17, 0 * 16));
  __ Ldr(q3, MemOperand(x17, 1 * 16));
  __ Ldr(q4, MemOperand(x17, 2 * 16));
  __ Ldr(q5, MemOperand(x17, 3 * 16));

  // Test H stores with and without post index.
  __ Mov(x0, 4);
  for (int i = 7; i >= 0; i--) {
    __ St2(v0.H(), v1.H(), i, MemOperand(x19));
    __ Add(x19, x19, 4);
  }
  for (int i = 7; i >= 0; i--) {
    __ St2(v0.H(), v1.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q6, MemOperand(x17, 4 * 16));
  __ Ldr(q7, MemOperand(x17, 5 * 16));
  __ Ldr(q16, MemOperand(x17, 6 * 16));
  __ Ldr(q17, MemOperand(x17, 7 * 16));

  // Test S stores with and without post index.
  for (int i = 3; i >= 0; i--) {
    __ St2(v0.S(), v1.S(), i, MemOperand(x19));
    __ Add(x19, x19, 8);
  }
  for (int i = 3; i >= 0; i--) {
    __ St2(v0.S(), v1.S(), i, MemOperand(x19, 8, PostIndex));
  }
  __ Ldr(q18, MemOperand(x17, 8 * 16));
  __ Ldr(q19, MemOperand(x17, 9 * 16));
  __ Ldr(q20, MemOperand(x17, 10 * 16));
  __ Ldr(q21, MemOperand(x17, 11 * 16));

  // Test D stores with and without post index.
  __ Mov(x0, 16);
  __ St2(v0.D(), v1.D(), 1, MemOperand(x19));
  __ Add(x19, x19, 16);
  __ St2(v0.D(), v1.D(), 0, MemOperand(x19, 16, PostIndex));
  __ St2(v0.D(), v1.D(), 1, MemOperand(x19, x0, PostIndex));
  __ St2(v0.D(), v1.D(), 0, MemOperand(x19, x0, PostIndex));
  __ Ldr(q22, MemOperand(x17, 12 * 16));
  __ Ldr(q23, MemOperand(x17, 13 * 16));
  __ Ldr(q24, MemOperand(x17, 14 * 16));
  __ Ldr(q25, MemOperand(x17, 15 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q2);
  CHECK_EQUAL_128(0x1F0F1E0E1D0D1C0C, 0x1B0B1A0A19091808, q3);
  CHECK_EQUAL_128(0x1707160615051404, 0x1303120211011000, q4);
  CHECK_EQUAL_128(0x1F0F1E0E1D0D1C0C, 0x1B0B1A0A19091808, q5);

  CHECK_EQUAL_128(0x1617060714150405, 0x1213020310110001, q6);
  CHECK_EQUAL_128(0x1E1F0E0F1C1D0C0D, 0x1A1B0A0B18190809, q7);
  CHECK_EQUAL_128(0x1617060714150405, 0x1213020310110001, q16);
  CHECK_EQUAL_128(0x1E1F0E0F1C1D0C0D, 0x1A1B0A0B18190809, q17);

  CHECK_EQUAL_128(0x1415161704050607, 0x1011121300010203, q18);
  CHECK_EQUAL_128(0x1C1D1E1F0C0D0E0F, 0x18191A1B08090A0B, q19);
  CHECK_EQUAL_128(0x1415161704050607, 0x1011121300010203, q20);
  CHECK_EQUAL_128(0x1C1D1E1F0C0D0E0F, 0x18191A1B08090A0B, q21);

  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q22);
  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q23);
  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q22);
  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q23);
}

TEST(neon_st3_lane) {
  INIT_V8();
  SETUP();

  // Struct size * addressing modes * element sizes * vector size.
  uint8_t dst[3 * 2 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);
  __ Movi(v2.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);

  // Test B stores with and without post index.
  for (int i = 15; i >= 0; i--) {
    __ St3(v0.B(), v1.B(), v2.B(), i, MemOperand(x19));
    __ Add(x19, x19, 3);
  }
  for (int i = 15; i >= 0; i--) {
    __ St3(v0.B(), v1.B(), v2.B(), i, MemOperand(x19, 3, PostIndex));
  }
  __ Ldr(q3, MemOperand(x17, 0 * 16));
  __ Ldr(q4, MemOperand(x17, 1 * 16));
  __ Ldr(q5, MemOperand(x17, 2 * 16));
  __ Ldr(q6, MemOperand(x17, 3 * 16));
  __ Ldr(q7, MemOperand(x17, 4 * 16));
  __ Ldr(q16, MemOperand(x17, 5 * 16));

  // Test H stores with and without post index.
  __ Mov(x0, 6);
  for (int i = 7; i >= 0; i--) {
    __ St3(v0.H(), v1.H(), v2.H(), i, MemOperand(x19));
    __ Add(x19, x19, 6);
  }
  for (int i = 7; i >= 0; i--) {
    __ St3(v0.H(), v1.H(), v2.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q17, MemOperand(x17, 6 * 16));
  __ Ldr(q18, MemOperand(x17, 7 * 16));
  __ Ldr(q19, MemOperand(x17, 8 * 16));
  __ Ldr(q20, MemOperand(x17, 9 * 16));
  __ Ldr(q21, MemOperand(x17, 10 * 16));
  __ Ldr(q22, MemOperand(x17, 11 * 16));

  // Test S stores with and without post index.
  for (int i = 3; i >= 0; i--) {
    __ St3(v0.S(), v1.S(), v2.S(), i, MemOperand(x19));
    __ Add(x19, x19, 12);
  }
  for (int i = 3; i >= 0; i--) {
    __ St3(v0.S(), v1.S(), v2.S(), i, MemOperand(x19, 12, PostIndex));
  }
  __ Ldr(q23, MemOperand(x17, 12 * 16));
  __ Ldr(q24, MemOperand(x17, 13 * 16));
  __ Ldr(q25, MemOperand(x17, 14 * 16));
  __ Ldr(q26, MemOperand(x17, 15 * 16));
  __ Ldr(q27, MemOperand(x17, 16 * 16));
  __ Ldr(q28, MemOperand(x17, 17 * 16));

  // Test D stores with and without post index.
  __ Mov(x0, 24);
  __ St3(v0.D(), v1.D(), v2.D(), 1, MemOperand(x19));
  __ Add(x19, x19, 24);
  __ St3(v0.D(), v1.D(), v2.D(), 0, MemOperand(x19, 24, PostIndex));
  __ St3(v0.D(), v1.D(), v2.D(), 1, MemOperand(x19, x0, PostIndex));
  __ Ldr(q29, MemOperand(x17, 18 * 16));
  __ Ldr(q30, MemOperand(x17, 19 * 16));
  __ Ldr(q31, MemOperand(x17, 20 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x0524140423130322, 0x1202211101201000, q3);
  CHECK_EQUAL_128(0x1A0A291909281808, 0x2717072616062515, q4);
  CHECK_EQUAL_128(0x2F1F0F2E1E0E2D1D, 0x0D2C1C0C2B1B0B2A, q5);
  CHECK_EQUAL_128(0x0524140423130322, 0x1202211101201000, q6);
  CHECK_EQUAL_128(0x1A0A291909281808, 0x2717072616062515, q7);
  CHECK_EQUAL_128(0x2F1F0F2E1E0E2D1D, 0x0D2C1C0C2B1B0B2A, q16);

  CHECK_EQUAL_128(0x1415040522231213, 0x0203202110110001, q17);
  CHECK_EQUAL_128(0x0A0B282918190809, 0x2627161706072425, q18);
  CHECK_EQUAL_128(0x2E2F1E1F0E0F2C2D, 0x1C1D0C0D2A2B1A1B, q19);
  CHECK_EQUAL_128(0x1415040522231213, 0x0203202110110001, q20);
  CHECK_EQUAL_128(0x0A0B282918190809, 0x2627161706072425, q21);
  CHECK_EQUAL_128(0x2E2F1E1F0E0F2C2D, 0x1C1D0C0D2A2B1A1B, q22);

  CHECK_EQUAL_128(0x0405060720212223, 0x1011121300010203, q23);
  CHECK_EQUAL_128(0x18191A1B08090A0B, 0x2425262714151617, q24);
  CHECK_EQUAL_128(0x2C2D2E2F1C1D1E1F, 0x0C0D0E0F28292A2B, q25);
  CHECK_EQUAL_128(0x0405060720212223, 0x1011121300010203, q26);
  CHECK_EQUAL_128(0x18191A1B08090A0B, 0x2425262714151617, q27);
  CHECK_EQUAL_128(0x2C2D2E2F1C1D1E1F, 0x0C0D0E0F28292A2B, q28);
}

TEST(neon_st4_lane) {
  INIT_V8();
  SETUP();

  // Struct size * element sizes * vector size.
  uint8_t dst[4 * 4 * 16];
  memset(dst, 0, sizeof(dst));
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, dst_base);
  __ Mov(x19, dst_base);
  __ Movi(v0.V2D(), 0x0001020304050607, 0x08090A0B0C0D0E0F);
  __ Movi(v1.V2D(), 0x1011121314151617, 0x18191A1B1C1D1E1F);
  __ Movi(v2.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);
  __ Movi(v3.V2D(), 0x2021222324252627, 0x28292A2B2C2D2E2F);

  // Test B stores without post index.
  for (int i = 15; i >= 0; i--) {
    __ St4(v0.B(), v1.B(), v2.B(), v3.B(), i, MemOperand(x19));
    __ Add(x19, x19, 4);
  }
  __ Ldr(q4, MemOperand(x17, 0 * 16));
  __ Ldr(q5, MemOperand(x17, 1 * 16));
  __ Ldr(q6, MemOperand(x17, 2 * 16));
  __ Ldr(q7, MemOperand(x17, 3 * 16));

  // Test H stores with post index.
  __ Mov(x0, 8);
  for (int i = 7; i >= 0; i--) {
    __ St4(v0.H(), v1.H(), v2.H(), v3.H(), i, MemOperand(x19, x0, PostIndex));
  }
  __ Ldr(q16, MemOperand(x17, 4 * 16));
  __ Ldr(q17, MemOperand(x17, 5 * 16));
  __ Ldr(q18, MemOperand(x17, 6 * 16));
  __ Ldr(q19, MemOperand(x17, 7 * 16));

  // Test S stores without post index.
  for (int i = 3; i >= 0; i--) {
    __ St4(v0.S(), v1.S(), v2.S(), v3.S(), i, MemOperand(x19));
    __ Add(x19, x19, 16);
  }
  __ Ldr(q20, MemOperand(x17, 8 * 16));
  __ Ldr(q21, MemOperand(x17, 9 * 16));
  __ Ldr(q22, MemOperand(x17, 10 * 16));
  __ Ldr(q23, MemOperand(x17, 11 * 16));

  // Test D stores with post index.
  __ Mov(x0, 32);
  __ St4(v0.D(), v1.D(), v2.D(), v3.D(), 0, MemOperand(x19, 32, PostIndex));
  __ St4(v0.D(), v1.D(), v2.D(), v3.D(), 1, MemOperand(x19, x0, PostIndex));

  __ Ldr(q24, MemOperand(x17, 12 * 16));
  __ Ldr(q25, MemOperand(x17, 13 * 16));
  __ Ldr(q26, MemOperand(x17, 14 * 16));
  __ Ldr(q27, MemOperand(x17, 15 * 16));
  END();

  RUN();

  CHECK_EQUAL_128(0x2323130322221202, 0x2121110120201000, q4);
  CHECK_EQUAL_128(0x2727170726261606, 0x2525150524241404, q5);
  CHECK_EQUAL_128(0x2B2B1B0B2A2A1A0A, 0x2929190928281808, q6);
  CHECK_EQUAL_128(0x2F2F1F0F2E2E1E0E, 0x2D2D1D0D2C2C1C0C, q7);

  CHECK_EQUAL_128(0x2223222312130203, 0x2021202110110001, q16);
  CHECK_EQUAL_128(0x2627262716170607, 0x2425242514150405, q17);
  CHECK_EQUAL_128(0x2A2B2A2B1A1B0A0B, 0x2829282918190809, q18);
  CHECK_EQUAL_128(0x2E2F2E2F1E1F0E0F, 0x2C2D2C2D1C1D0C0D, q19);

  CHECK_EQUAL_128(0x2021222320212223, 0x1011121300010203, q20);
  CHECK_EQUAL_128(0x2425262724252627, 0x1415161704050607, q21);
  CHECK_EQUAL_128(0x28292A2B28292A2B, 0x18191A1B08090A0B, q22);
  CHECK_EQUAL_128(0x2C2D2E2F2C2D2E2F, 0x1C1D1E1F0C0D0E0F, q23);

  CHECK_EQUAL_128(0x18191A1B1C1D1E1F, 0x08090A0B0C0D0E0F, q24);
  CHECK_EQUAL_128(0x28292A2B2C2D2E2F, 0x28292A2B2C2D2E2F, q25);
  CHECK_EQUAL_128(0x1011121314151617, 0x0001020304050607, q26);
  CHECK_EQUAL_128(0x2021222324252627, 0x2021222324252627, q27);
}

TEST(neon_ld1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, src_base);
  __ Mov(x19, src_base);
  __ Mov(x20, src_base);
  __ Mov(x21, src_base);
  __ Mov(x22, src_base);
  __ Mov(x23, src_base);
  __ Mov(x24, src_base);

  // Test loading whole register by element.
  for (int i = 15; i >= 0; i--) {
    __ Ld1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }

  for (int i = 7; i >= 0; i--) {
    __ Ld1(v1.H(), i, MemOperand(x28, 2, PostIndex));
  }

  for (int i = 3; i >= 0; i--) {
    __ Ld1(v2.S(), i, MemOperand(x19, 4, PostIndex));
  }

  for (int i = 1; i >= 0; i--) {
    __ Ld1(v3.D(), i, MemOperand(x20, 8, PostIndex));
  }

  // Test loading a single element into an initialised register.
  __ Mov(x25, 1);
  __ Ldr(q4, MemOperand(x21));
  __ Ld1(v4.B(), 4, MemOperand(x21, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q5, MemOperand(x22));
  __ Ld1(v5.H(), 3, MemOperand(x22, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q6, MemOperand(x23));
  __ Ld1(v6.S(), 2, MemOperand(x23, x25, PostIndex));
  __ Add(x25, x25, 1);

  __ Ldr(q7, MemOperand(x24));
  __ Ld1(v7.D(), 1, MemOperand(x24, x25, PostIndex));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q0);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q1);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q2);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q3);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050003020100, q4);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0100050403020100, q5);
  CHECK_EQUAL_128(0x0F0E0D0C03020100, 0x0706050403020100, q6);
  CHECK_EQUAL_128(0x0706050403020100, 0x0706050403020100, q7);
  CHECK_EQUAL_64(src_base + 16, x17);
  CHECK_EQUAL_64(src_base + 16, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(src_base + 16, x20);
  CHECK_EQUAL_64(src_base + 1, x21);
  CHECK_EQUAL_64(src_base + 2, x22);
  CHECK_EQUAL_64(src_base + 3, x23);
  CHECK_EQUAL_64(src_base + 4, x24);
}

TEST(neon_st1_lane_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x19, -16);
  __ Ldr(q0, MemOperand(x17));

  for (int i = 15; i >= 0; i--) {
    __ St1(v0.B(), i, MemOperand(x17, 1, PostIndex));
  }
  __ Ldr(q1, MemOperand(x17, x19));

  for (int i = 7; i >= 0; i--) {
    __ St1(v0.H(), i, MemOperand(x17, 2, PostIndex));
  }
  __ Ldr(q2, MemOperand(x17, x19));

  for (int i = 3; i >= 0; i--) {
    __ St1(v0.S(), i, MemOperand(x17, 4, PostIndex));
  }
  __ Ldr(q3, MemOperand(x17, x19));

  for (int i = 1; i >= 0; i--) {
    __ St1(v0.D(), i, MemOperand(x17, 8, PostIndex));
  }
  __ Ldr(q4, MemOperand(x17, x19));

  END();

  RUN();

  CHECK_EQUAL_128(0x0001020304050607, 0x08090A0B0C0D0E0F, q1);
  CHECK_EQUAL_128(0x0100030205040706, 0x09080B0A0D0C0F0E, q2);
  CHECK_EQUAL_128(0x0302010007060504, 0x0B0A09080F0E0D0C, q3);
  CHECK_EQUAL_128(0x0706050403020100, 0x0F0E0D0C0B0A0908, q4);
}

TEST(neon_ld1_alllanes) {
  INIT_V8();
  SETUP();

  uint8_t src[64];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base + 1);
  __ Ld1r(v0.V8B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v1.V16B(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v2.V4H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v3.V8H(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v4.V2S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v5.V4S(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v6.V1D(), MemOperand(x17));
  __ Add(x17, x17, 1);
  __ Ld1r(v7.V2D(), MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0807060508070605, q4);
  CHECK_EQUAL_128(0x0908070609080706, 0x0908070609080706, q5);
  CHECK_EQUAL_128(0, 0x0E0D0C0B0A090807, q6);
  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0F0E0D0C0B0A0908, q7);
}

TEST(neon_ld1_alllanes_postindex) {
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
  __ Ld1r(v0.V8B(), MemOperand(x17, 1, PostIndex));
  __ Ld1r(v1.V16B(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v2.V4H(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v3.V8H(), MemOperand(x17, 2, PostIndex));
  __ Ld1r(v4.V2S(), MemOperand(x17, x19, PostIndex));
  __ Ld1r(v5.V4S(), MemOperand(x17, 4, PostIndex));
  __ Ld1r(v6.V2D(), MemOperand(x17, 8, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0101010101010101, q0);
  CHECK_EQUAL_128(0x0202020202020202, 0x0202020202020202, q1);
  CHECK_EQUAL_128(0, 0x0403040304030403, q2);
  CHECK_EQUAL_128(0x0504050405040504, 0x0504050405040504, q3);
  CHECK_EQUAL_128(0, 0x0908070609080706, q4);
  CHECK_EQUAL_128(0x0A0908070A090807, 0x0A0908070A090807, q5);
  CHECK_EQUAL_128(0x1211100F0E0D0C0B, 0x1211100F0E0D0C0B, q6);
  CHECK_EQUAL_64(src_base + 19, x17);
}

TEST(neon_st1_d) {
  INIT_V8();
  SETUP();

  uint8_t src[14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17));
  __ Ldr(d16, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17));
  __ Ldr(d18, MemOperand(x17, 8, PostIndex));
  __ Ldr(d19, MemOperand(x17, 8, PostIndex));
  __ Ldr(d20, MemOperand(x17, 8, PostIndex));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(), MemOperand(x17));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(), MemOperand(x17));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17));
  END();

  RUN();

  CHECK_EQUAL_128(0x0F0E0D0C0B0A0908, 0x0706050403020100, q0);
  CHECK_EQUAL_128(0x1F1E1D1C1B1A1918, 0x1716151413121110, q1);
  CHECK_EQUAL_128(0x2F2E2D2C2B2A2928, 0x2726252423222120, q2);
  CHECK_EQUAL_128(0x3F3E3D3C3B3A3938, 0x3736353433323130, q3);
  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_d_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 14 * kDRegSize];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -8);
  __ Mov(x19, -16);
  __ Mov(x20, -24);
  __ Mov(x21, -32);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));
  __ Mov(x17, src_base);

  __ St1(v0.V8B(), MemOperand(x17, 8, PostIndex));
  __ Ldr(d16, MemOperand(x17, x28));

  __ St1(v0.V8B(), v1.V8B(), MemOperand(x17, 16, PostIndex));
  __ Ldr(q17, MemOperand(x17, x19));

  __ St1(v0.V4H(), v1.V4H(), v2.V4H(), MemOperand(x17, 24, PostIndex));
  __ Ldr(d18, MemOperand(x17, x20));
  __ Ldr(d19, MemOperand(x17, x19));
  __ Ldr(d20, MemOperand(x17, x28));

  __ St1(v0.V2S(), v1.V2S(), v2.V2S(), v3.V2S(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q21, MemOperand(x17, x21));
  __ Ldr(q22, MemOperand(x17, x19));

  __ St1(v0.V1D(), v1.V1D(), v2.V1D(), v3.V1D(),
         MemOperand(x17, 32, PostIndex));
  __ Ldr(q23, MemOperand(x17, x21));
  __ Ldr(q24, MemOperand(x17, x19));
  END();

  RUN();

  CHECK_EQUAL_128(0, 0x0706050403020100, q16);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q17);
  CHECK_EQUAL_128(0, 0x0706050403020100, q18);
  CHECK_EQUAL_128(0, 0x1716151413121110, q19);
  CHECK_EQUAL_128(0, 0x2726252423222120, q20);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q21);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q22);
  CHECK_EQUAL_128(0x1716151413121110, 0x0706050403020100, q23);
  CHECK_EQUAL_128(0x3736353433323130, 0x2726252423222120, q24);
}

TEST(neon_st1_q) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Ldr(q0, MemOperand(x17, 16, PostIndex));
  __ Ldr(q1, MemOperand(x17, 16, PostIndex));
  __ Ldr(q2, MemOperand(x17, 16, PostIndex));
  __ Ldr(q3, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V16B(), MemOperand(x17));
  __ Ldr(q16, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V8H(), v1.V8H(), MemOperand(x17));
  __ Ldr(q17, MemOperand(x17, 16, PostIndex));
  __ Ldr(q18, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V4S(), v1.V4S(), v2.V4S(), MemOperand(x17));
  __ Ldr(q19, MemOperand(x17, 16, PostIndex));
  __ Ldr(q20, MemOperand(x17, 16, PostIndex));
  __ Ldr(q21, MemOperand(x17, 16, PostIndex));

  __ St1(v0.V2D(), v1.V2D(), v2.V2D(), v3.V2D(), MemOperand(x17));
  __ Ldr(q22, MemOperand(x17, 16, PostIndex));
  __ Ldr(q23, MemOperand(x17, 16, PostIndex));
  __ Ldr(q24, MemOperand(x17, 16, PostIndex));
  __ Ldr(q25, MemOperand(x17));
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

TEST(neon_st1_q_postindex) {
  INIT_V8();
  SETUP();

  uint8_t src[64 + 160];
  for (unsigned i = 0; i < sizeof(src); i++) {
    src[i] = i;
  }
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, -16);
 
"""


```