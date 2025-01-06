Response:
My thought process for analyzing the provided C++ code snippet went through these stages:

1. **Identify the Core Purpose:** The file name `disasm-arm64-unittest.cc` and the use of `TEST_F` immediately suggest this is a unit test file specifically for the ARM64 disassembler within the V8 JavaScript engine. The "disasm" part is key.

2. **Recognize the Testing Framework:** The `TEST_F` macro indicates the use of Google Test. The structure `TEST_F(ClassName, TestName) { ... }` is the standard way to define tests in this framework. The `DisasmArm64Test` class name reinforces the focus on ARM64 disassembly.

3. **Analyze the `barriers` Test:**
    * The `SET_UP_MASM()` and `CLEANUP()` calls suggest the test involves setting up and tearing down some kind of assembler context or environment. `masm` often refers to a macro assembler.
    * The `COMPARE(instruction, expected_disassembly)` pattern is the heart of the test. It implies that the test is generating ARM64 instructions and then comparing the output of the disassembler against a known correct string representation.
    * The specific instructions being tested (`DMB`, `DSB`, `ISB`, `CSDB`) are memory barrier instructions used for ensuring proper ordering of memory operations in multi-core systems. The different arguments to `Dmb` and `Dsb` (e.g., `FullSystem`, `InnerShareable`, `BarrierAll`, `BarrierReads`) represent different levels of memory barrier strength and scope.

4. **Analyze the `neon_load_store_vector` Test:**
    * Again, `SET_UP_MASM()` and `CLEANUP()` are present.
    * The `COMPARE` macro is used extensively.
    * The tested instructions (`Ld1`, `Ld2`, `Ld3`, `Ld4`, `St1`, `St2`, `St3`, `St4`) are NEON (Advanced SIMD) load and store instructions. The numbers 1-4 indicate loading/storing 1 to 4 registers at once.
    * The `.M` suffixes on the `v` registers (`v0.M`, `v1.M`, etc.) and the `S` arguments in the `COMPARE` strings (`"8b"`, `"16b"`, `"4h"`, etc.) refer to different data types and sizes within the NEON registers (e.g., 8-bit bytes, 16-bit halfwords, etc.).
    * The `MemOperand` objects define the memory addresses being accessed, with variations for base registers, immediate offsets, and post-increment addressing modes.

5. **Analyze the `neon_load_store_vector_unallocated` Test:**
    * `SET_UP_MASM()` and `CLEANUP()`.
    * The `dci(opcode)` function seems to be injecting raw instruction opcodes.
    * The `COMPARE(dci(opcode), "unallocated (...)")` pattern suggests this test is verifying that the disassembler correctly identifies certain opcodes as "unallocated" or invalid for specific NEON load/store instructions. This is important for error handling.

6. **Analyze the `neon_load_store_lane` Test:**
    * `SET_UP_MASM()` and `CLEANUP()`.
    * The instructions (`Ld1`, `Ld2`, `Ld3`, `Ld4`, `St1`) are again NEON load/store, but this time they operate on individual *lanes* (elements) within the vector registers, as indicated by the `[index]` notation in the disassembled strings (e.g., `{v0.b}[0]`).

7. **Address Specific Instructions:**
    * **.tq extension:**  The code is `.cc`, so it's C++, not Torque.
    * **JavaScript relation:**  These tests are for the *internal* disassembler used by V8. While not directly writing JavaScript, understanding the output helps debug the generated machine code from JavaScript execution. I thought about how a JavaScript engine uses a disassembler (for debugging, JIT compilation verification, etc.).
    * **Code logic and I/O:** The core logic is generating instructions and comparing the disassembled output. I considered simple examples for each type of instruction.
    * **Common programming errors:** I thought about errors related to memory barriers (e.g., incorrect ordering) and NEON instructions (e.g., type mismatches, out-of-bounds lane access).

8. **Synthesize the Overall Function:** Based on the individual tests, I concluded that the primary function of this file is to test the ARM64 disassembler in V8, specifically its ability to correctly translate machine code instructions back into a human-readable assembly language format. It covers various instruction types, including memory barriers and NEON load/store instructions, including different addressing modes and data types.

9. **Consider the "Part 4 of 8" Context:** This suggests that there are other related unit test files covering other aspects of the ARM64 assembler and disassembler. This part specifically focuses on memory barriers and NEON load/store instructions.

By following these steps, I could systematically analyze the code, understand its purpose, and generate the comprehensive explanation you provided. The key was to break down the code into smaller, manageable parts (the individual `TEST_F` blocks) and then generalize the findings.这是v8/test/unittests/assembler/disasm-arm64-unittest.cc的第4部分，主要功能是**测试V8 JavaScript引擎中ARM64架构的反汇编器 (disassembler) 的正确性**。

更具体地说，这部分代码测试了反汇编器对以下ARM64指令的解析和格式化输出：

* **内存屏障指令 (Memory Barrier Instructions):**  `DMB`, `DSB`, `ISB`, `CSDB`。这些指令用于确保多核处理器系统中内存操作的顺序，防止数据竞争等问题。
* **NEON (Advanced SIMD) 向量加载和存储指令 (Vector Load and Store Instructions):** `LD1`, `LD2`, `LD3`, `LD4`, `ST1`, `ST2`, `ST3`, `ST4`。 这些指令用于高效地加载和存储向量数据到NEON寄存器中，常用于并行计算和多媒体处理。测试涵盖了不同的数据类型（字节、半字、字、双字）和不同的寻址模式（立即数偏移、寄存器偏移、后索引）。
* **NEON 向量Lane (元素) 加载和存储指令 (Vector Lane Load and Store Instructions):**  `LD1`, `LD2`, `LD3`, `LD4`, `ST1` 的变体，用于访问和操作向量寄存器中的单个元素（lane）。

**功能归纳:**

这部分单元测试主要验证了 V8 的 ARM64 反汇编器能够正确地将 ARM64 机器码指令（特别是内存屏障指令和NEON向量加载/存储指令）转换成易于理解的汇编语言文本表示。  它通过构造特定的指令，然后断言反汇编器的输出是否与预期的字符串匹配来实现。

**关于其他问题：**

* **.tq 结尾:**  `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。Torque 文件通常以 `.tq` 结尾。
* **与 JavaScript 的关系:**  反汇编器是 V8 引擎内部的一个组件，用于将机器码转换回汇编代码。虽然它不是直接编写 JavaScript 代码，但它与 JavaScript 的执行密切相关。当 V8 执行 JavaScript 代码时，它会将 JavaScript 代码编译成机器码。为了调试、性能分析或理解生成的机器码，就需要用到反汇编器。例如，开发者可以使用 V8 提供的工具来查看 JavaScript 函数被编译后的 ARM64 指令。
* **JavaScript 示例 (概念性):**  虽然无法直接用 JavaScript 模拟这个 C++ 单元测试，但可以理解反汇编器在 V8 中的作用。想象一下，你有一段 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

V8 在执行这段代码时，会将 `add` 函数编译成 ARM64 机器码。  反汇编器可以将这些机器码转换成类似下面的汇编指令（简化示例）：

```assembly
// ... 函数序言 ...
ldr w0, [sp, #offset_a]  // 加载参数 a 到 w0 寄存器
ldr w1, [sp, #offset_b]  // 加载参数 b 到 w1 寄存器
add w0, w0, w1          // 将 w0 和 w1 相加，结果存回 w0
str w0, [sp, #offset_result] // 将结果存储到栈上
// ... 函数尾声 ...
ret                     // 返回
```

这个 C++ 单元测试就是在验证 V8 内部的反汇编器能否正确地将 V8 生成的实际机器码转换成类似的汇编表示。

* **代码逻辑推理 (假设输入与输出):**

   **假设输入 (C++ 代码中的指令构造):**
   例如： `Dmb(FullSystem, BarrierAll)`

   **内部处理:**  V8 的汇编器会将 `Dmb(FullSystem, BarrierAll)` 编译成对应的 ARM64 机器码，然后反汇编器会尝试将这段机器码转换回汇编。

   **预期输出 (COMPARE 宏中的字符串):**
   `"dmb sy"`

   `COMPARE` 宏会比较反汇编器的实际输出和预期的 `"dmb sy"` 字符串，如果一致则测试通过。

* **涉及用户常见的编程错误 (概念性):**  虽然这个单元测试是针对 V8 内部的反汇编器，但内存屏障和 NEON 指令的使用不当是用户在编写底层代码或进行性能优化时可能遇到的错误。

   * **内存屏障错误:** 如果没有正确使用内存屏障，在多线程或多核环境下可能会导致数据竞争和不可预测的结果。例如，一个线程写入了数据，但另一个线程可能在没有内存屏障的情况下读取到旧的数据。

   * **NEON 指令错误:**
      * **数据类型不匹配:**  尝试对不同大小或类型的向量进行操作。
      * **访问越界:**  尝试访问向量中不存在的 Lane。
      * **指令使用不当:**  错误地使用了 NEON 指令，导致计算结果不正确。

**总结第4部分的功能:**

这部分单元测试的核心目标是确保 V8 JavaScript 引擎中的 ARM64 反汇编器能够准确无误地解析和格式化输出内存屏障指令和 NEON 向量加载/存储指令。这对于 V8 引擎的正确性和可调试性至关重要。

Prompt: 
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""

}

TEST_F(DisasmArm64Test, barriers) {
  SET_UP_MASM();

  // DMB
  COMPARE(Dmb(FullSystem, BarrierAll), "dmb sy");
  COMPARE(Dmb(FullSystem, BarrierReads), "dmb ld");
  COMPARE(Dmb(FullSystem, BarrierWrites), "dmb st");

  COMPARE(Dmb(InnerShareable, BarrierAll), "dmb ish");
  COMPARE(Dmb(InnerShareable, BarrierReads), "dmb ishld");
  COMPARE(Dmb(InnerShareable, BarrierWrites), "dmb ishst");

  COMPARE(Dmb(NonShareable, BarrierAll), "dmb nsh");
  COMPARE(Dmb(NonShareable, BarrierReads), "dmb nshld");
  COMPARE(Dmb(NonShareable, BarrierWrites), "dmb nshst");

  COMPARE(Dmb(OuterShareable, BarrierAll), "dmb osh");
  COMPARE(Dmb(OuterShareable, BarrierReads), "dmb oshld");
  COMPARE(Dmb(OuterShareable, BarrierWrites), "dmb oshst");

  COMPARE(Dmb(FullSystem, BarrierOther), "dmb sy (0b1100)");
  COMPARE(Dmb(InnerShareable, BarrierOther), "dmb sy (0b1000)");
  COMPARE(Dmb(NonShareable, BarrierOther), "dmb sy (0b0100)");
  COMPARE(Dmb(OuterShareable, BarrierOther), "dmb sy (0b0000)");

  // DSB
  COMPARE(Dsb(FullSystem, BarrierAll), "dsb sy");
  COMPARE(Dsb(FullSystem, BarrierReads), "dsb ld");
  COMPARE(Dsb(FullSystem, BarrierWrites), "dsb st");

  COMPARE(Dsb(InnerShareable, BarrierAll), "dsb ish");
  COMPARE(Dsb(InnerShareable, BarrierReads), "dsb ishld");
  COMPARE(Dsb(InnerShareable, BarrierWrites), "dsb ishst");

  COMPARE(Dsb(NonShareable, BarrierAll), "dsb nsh");
  COMPARE(Dsb(NonShareable, BarrierReads), "dsb nshld");
  COMPARE(Dsb(NonShareable, BarrierWrites), "dsb nshst");

  COMPARE(Dsb(OuterShareable, BarrierAll), "dsb osh");
  COMPARE(Dsb(OuterShareable, BarrierReads), "dsb oshld");
  COMPARE(Dsb(OuterShareable, BarrierWrites), "dsb oshst");

  COMPARE(Dsb(FullSystem, BarrierOther), "dsb sy (0b1100)");
  COMPARE(Dsb(InnerShareable, BarrierOther), "dsb sy (0b1000)");
  COMPARE(Dsb(NonShareable, BarrierOther), "dsb sy (0b0100)");
  COMPARE(Dsb(OuterShareable, BarrierOther), "dsb sy (0b0000)");

  // ISB
  COMPARE(Isb(), "isb");

  // CSDB
  COMPARE(Csdb(), "csdb");

  CLEANUP();
}

#define VLIST2(v) \
  v, VRegister::Create((v.code() + 1) % 32, v.SizeInBits(), v.LaneCount())
#define VLIST3(v) \
  VLIST2(v)       \
  , VRegister::Create((v.code() + 2) % 32, v.SizeInBits(), v.LaneCount())
#define VLIST4(v) \
  VLIST3(v)       \
  , VRegister::Create((v.code() + 3) % 32, v.SizeInBits(), v.LaneCount())

#define NEON_FORMAT_LIST(V) \
  V(V8B(), "8b")            \
  V(V16B(), "16b")          \
  V(V4H(), "4h")            \
  V(V8H(), "8h")            \
  V(V2S(), "2s")            \
  V(V4S(), "4s")            \
  V(V2D(), "2d")

#define NEON_FORMAT_LIST_LP(V)  \
  V(V4H(), "4h", V8B(), "8b")   \
  V(V2S(), "2s", V4H(), "4h")   \
  V(V1D(), "1d", V2S(), "2s")   \
  V(V8H(), "8h", V16B(), "16b") \
  V(V4S(), "4s", V8H(), "8h")   \
  V(V2D(), "2d", V4S(), "4s")

#define NEON_FORMAT_LIST_LW(V) \
  V(V8H(), "8h", V8B(), "8b")  \
  V(V4S(), "4s", V4H(), "4h")  \
  V(V2D(), "2d", V2S(), "2s")

#define NEON_FORMAT_LIST_LW2(V) \
  V(V8H(), "8h", V16B(), "16b") \
  V(V4S(), "4s", V8H(), "8h")   \
  V(V2D(), "2d", V4S(), "4s")

#define NEON_FORMAT_LIST_BHS(V) \
  V(V8B(), "8b")                \
  V(V16B(), "16b")              \
  V(V4H(), "4h")                \
  V(V8H(), "8h")                \
  V(V2S(), "2s")                \
  V(V4S(), "4s")

#define NEON_FORMAT_LIST_HS(V) \
  V(V4H(), "4h")               \
  V(V8H(), "8h")               \
  V(V2S(), "2s")               \
  V(V4S(), "4s")

#define NEON_FORMAT_LIST_FP(V) \
  V(V4H(), "4h")               \
  V(V8H(), "8h")               \
  V(V2S(), "2s")               \
  V(V4S(), "4s")               \
  V(V2D(), "2d")

TEST_F(DisasmArm64Test, neon_load_store_vector) {
  SET_UP_MASM();

#define DISASM_INST(M, S)                                         \
  COMPARE(Ld1(v0.M, MemOperand(x15)), "ld1 {v0." S "}, [x15]");   \
  COMPARE(Ld1(v1.M, v2.M, MemOperand(x16)),                       \
          "ld1 {v1." S ", v2." S "}, [x16]");                     \
  COMPARE(Ld1(v3.M, v4.M, v5.M, MemOperand(x17)),                 \
          "ld1 {v3." S ", v4." S ", v5." S "}, [x17]");           \
  COMPARE(Ld1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18)),          \
          "ld1 {v6." S ", v7." S ", v8_." S ", v9." S "}, [x18]") \
  COMPARE(Ld1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),          \
          "ld1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]") \
  COMPARE(Ld2(v1.M, v2.M, MemOperand(x16)),                       \
          "ld2 {v1." S ", v2." S "}, [x16]");                     \
  COMPARE(Ld3(v3.M, v4.M, v5.M, MemOperand(x17)),                 \
          "ld3 {v3." S ", v4." S ", v5." S "}, [x17]");           \
  COMPARE(Ld4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18)),          \
          "ld4 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18]")  \
  COMPARE(Ld4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),          \
          "ld4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]") \
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

#define DISASM_INST(M, S)                                                \
  COMPARE(Ld1(v0.M, MemOperand(x15, x20, PostIndex)),                    \
          "ld1 {v0." S "}, [x15], x20");                                 \
  COMPARE(Ld1(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "ld1 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(Ld1(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "ld1 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(Ld1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "ld1 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(Ld1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "ld1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  COMPARE(Ld2(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "ld2 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(Ld3(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "ld3 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(Ld4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "ld4 {v6." S ", v7." S ", v8_." S ", v9." S "}, [x18], x23")   \
  COMPARE(Ld4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "ld4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

  COMPARE(Ld1(v0.V8B(), MemOperand(x15, 8, PostIndex)),
          "ld1 {v0.8b}, [x15], #8");
  COMPARE(Ld1(v1.V16B(), MemOperand(x16, 16, PostIndex)),
          "ld1 {v1.16b}, [x16], #16");
  COMPARE(Ld1(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "ld1 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(Ld1(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "ld1 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(Ld1(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "ld1 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(Ld1(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "ld1 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(Ld1(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "ld1 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(Ld1(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "ld1 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(Ld2(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "ld2 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(Ld2(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "ld2 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(Ld3(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "ld3 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(Ld3(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "ld3 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(Ld4(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "ld4 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(Ld4(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "ld4 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(Ld1(v0.V1D(), MemOperand(x16)), "ld1 {v0.1d}, [x16]");
  COMPARE(Ld1(v1.V1D(), v2.V1D(), MemOperand(x17, 16, PostIndex)),
          "ld1 {v1.1d, v2.1d}, [x17], #16");
  COMPARE(Ld1(v3.V1D(), v4.V1D(), v5.V1D(), MemOperand(x18, x19, PostIndex)),
          "ld1 {v3.1d, v4.1d, v5.1d}, [x18], x19");
  COMPARE(Ld1(v30.V1D(), v31.V1D(), v0.V1D(), v1.V1D(),
              MemOperand(x20, 32, PostIndex)),
          "ld1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x20], #32");
  COMPARE(Ld1(d30, d31, d0, d1, MemOperand(x21, x22, PostIndex)),
          "ld1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x21], x22");

#define DISASM_INST(M, S)                                            \
  COMPARE(St1(v20.M, MemOperand(x15)), "st1 {v20." S "}, [x15]");    \
  COMPARE(St1(v21.M, v22.M, MemOperand(x16)),                        \
          "st1 {v21." S ", v22." S "}, [x16]");                      \
  COMPARE(St1(v23.M, v24.M, v25.M, MemOperand(x17)),                 \
          "st1 {v23." S ", v24." S ", v25." S "}, [x17]");           \
  COMPARE(St1(v26.M, v27.M, v28.M, v29.M, MemOperand(x18)),          \
          "st1 {v26." S ", v27." S ", v28." S ", v29." S "}, [x18]") \
  COMPARE(St1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),             \
          "st1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]")    \
  COMPARE(St2(VLIST2(v21.M), MemOperand(x16)),                       \
          "st2 {v21." S ", v22." S "}, [x16]");                      \
  COMPARE(St3(v23.M, v24.M, v25.M, MemOperand(x17)),                 \
          "st3 {v23." S ", v24." S ", v25." S "}, [x17]");           \
  COMPARE(St4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp)),             \
          "st4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp]")
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

#define DISASM_INST(M, S)                                                \
  COMPARE(St1(v0.M, MemOperand(x15, x20, PostIndex)),                    \
          "st1 {v0." S "}, [x15], x20");                                 \
  COMPARE(St1(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "st1 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(St1(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "st1 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(St1(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "st1 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(St1(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "st1 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")   \
  COMPARE(St2(v1.M, v2.M, MemOperand(x16, x21, PostIndex)),              \
          "st2 {v1." S ", v2." S "}, [x16], x21");                       \
  COMPARE(St3(v3.M, v4.M, v5.M, MemOperand(x17, x22, PostIndex)),        \
          "st3 {v3." S ", v4." S ", v5." S "}, [x17], x22");             \
  COMPARE(St4(v6.M, v7.M, v8_.M, v9.M, MemOperand(x18, x23, PostIndex)), \
          "st4 {v6." S ", v7." S ", v8." S ", v9." S "}, [x18], x23")    \
  COMPARE(St4(v30.M, v31.M, v0.M, v1.M, MemOperand(sp, x24, PostIndex)), \
          "st4 {v30." S ", v31." S ", v0." S ", v1." S "}, [sp], x24")
  NEON_FORMAT_LIST(DISASM_INST);
#undef DISASM_INST

  COMPARE(St1(v0.V8B(), MemOperand(x15, 8, PostIndex)),
          "st1 {v0.8b}, [x15], #8");
  COMPARE(St1(v1.V16B(), MemOperand(x16, 16, PostIndex)),
          "st1 {v1.16b}, [x16], #16");
  COMPARE(St1(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "st1 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(St1(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "st1 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(St1(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "st1 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(St1(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "st1 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(St1(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "st1 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(St1(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "st1 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");
  COMPARE(St2(v1.V16B(), v2.V16B(), MemOperand(x16, 32, PostIndex)),
          "st2 {v1.16b, v2.16b}, [x16], #32");
  COMPARE(St2(v2.V4H(), v3.V4H(), MemOperand(x17, 16, PostIndex)),
          "st2 {v2.4h, v3.4h}, [x17], #16");
  COMPARE(St2(v4.V8H(), v5.V8H(), MemOperand(x18, 32, PostIndex)),
          "st2 {v4.8h, v5.8h}, [x18], #32");
  COMPARE(St3(v16.V2S(), v17.V2S(), v18.V2S(), MemOperand(x19, 24, PostIndex)),
          "st3 {v16.2s, v17.2s, v18.2s}, [x19], #24");
  COMPARE(St3(v16.V4S(), v17.V4S(), v18.V4S(), MemOperand(x19, 48, PostIndex)),
          "st3 {v16.4s, v17.4s, v18.4s}, [x19], #48");
  COMPARE(St4(v19.V2S(), v20.V2S(), v21.V2S(), v22.V2S(),
              MemOperand(x20, 32, PostIndex)),
          "st4 {v19.2s, v20.2s, v21.2s, v22.2s}, [x20], #32");
  COMPARE(St4(v23.V2D(), v24.V2D(), v25.V2D(), v26.V2D(),
              MemOperand(x21, 64, PostIndex)),
          "st4 {v23.2d, v24.2d, v25.2d, v26.2d}, [x21], #64");

  COMPARE(St1(v0.V1D(), MemOperand(x16)), "st1 {v0.1d}, [x16]");
  COMPARE(St1(v1.V1D(), v2.V1D(), MemOperand(x17, 16, PostIndex)),
          "st1 {v1.1d, v2.1d}, [x17], #16");
  COMPARE(St1(v3.V1D(), v4.V1D(), v5.V1D(), MemOperand(x18, x19, PostIndex)),
          "st1 {v3.1d, v4.1d, v5.1d}, [x18], x19");
  COMPARE(St1(v30.V1D(), v31.V1D(), v0.V1D(), v1.V1D(),
              MemOperand(x20, 32, PostIndex)),
          "st1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x20], #32");
  COMPARE(St1(d30, d31, d0, d1, MemOperand(x21, x22, PostIndex)),
          "st1 {v30.1d, v31.1d, v0.1d, v1.1d}, [x21], x22");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_vector_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreMultiStruct)";
  // LD[1-4] (multiple structures) (no offset)
  COMPARE(dci(0x0c401000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c403000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c405000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c409000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c40b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c40c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c40d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c40e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c40f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c400c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c404c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c408c00), expected);  // opcode = 0b1000, size:Q = 0b110

  // ST[1-4] (multiple structures) (no offset)
  COMPARE(dci(0x0c001000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c003000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c005000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c009000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c00b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c00c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c00d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c00e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c00f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c000c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c004c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c008c00), expected);  // opcode = 0b1000, size:Q = 0b110

  expected = "unallocated (NEONLoadStoreMultiStructPostIndex)";
  // LD[1-4] (multiple structures) (post index)
  COMPARE(dci(0x0cc01000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0cc03000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0cc05000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0cc09000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0cc0b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0cc0c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0cc0d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0cc0e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0cc0f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0cc00c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0cc04c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0cc08c00), expected);  // opcode = 0b1000, size:Q = 0b110

  // ST[1-4] (multiple structures) (post index)
  COMPARE(dci(0x0c801000), expected);  // opcode = 0b0001
  COMPARE(dci(0x0c803000), expected);  // opcode = 0b0011
  COMPARE(dci(0x0c805000), expected);  // opcode = 0b0101
  COMPARE(dci(0x0c809000), expected);  // opcode = 0b1001
  COMPARE(dci(0x0c80b000), expected);  // opcode = 0b1011
  COMPARE(dci(0x0c80c000), expected);  // opcode = 0b1100
  COMPARE(dci(0x0c80d000), expected);  // opcode = 0b1101
  COMPARE(dci(0x0c80e000), expected);  // opcode = 0b1110
  COMPARE(dci(0x0c80f000), expected);  // opcode = 0b1111
  COMPARE(dci(0x0c800c00), expected);  // opcode = 0b0000, size:Q = 0b110
  COMPARE(dci(0x0c804c00), expected);  // opcode = 0b0100, size:Q = 0b110
  COMPARE(dci(0x0c808c00), expected);  // opcode = 0b1000, size:Q = 0b110

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_lane) {
  SET_UP_MASM();

  COMPARE(Ld1(v0.V8B(), 0, MemOperand(x15)), "ld1 {v0.b}[0], [x15]");
  COMPARE(Ld1(v1.V16B(), 1, MemOperand(x16)), "ld1 {v1.b}[1], [x16]");
  COMPARE(Ld1(v2.V4H(), 2, MemOperand(x17)), "ld1 {v2.h}[2], [x17]");
  COMPARE(Ld1(v3.V8H(), 3, MemOperand(x18)), "ld1 {v3.h}[3], [x18]");
  COMPARE(Ld1(v4.V2S(), 0, MemOperand(x19)), "ld1 {v4.s}[0], [x19]");
  COMPARE(Ld1(v5.V4S(), 1, MemOperand(x20)), "ld1 {v5.s}[1], [x20]");
  COMPARE(Ld1(v6.V2D(), 0, MemOperand(x21)), "ld1 {v6.d}[0], [x21]");
  COMPARE(Ld1(v7.B(), 7, MemOperand(x22)), "ld1 {v7.b}[7], [x22]");
  COMPARE(Ld1(v8_.B(), 15, MemOperand(x23)), "ld1 {v8.b}[15], [x23]");
  COMPARE(Ld1(v9.H(), 3, MemOperand(x24)), "ld1 {v9.h}[3], [x24]");
  COMPARE(Ld1(v10.H(), 7, MemOperand(x25)), "ld1 {v10.h}[7], [x25]");
  COMPARE(Ld1(v11.S(), 1, MemOperand(x26)), "ld1 {v11.s}[1], [x26]");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27)), "ld1 {v12.s}[3], [cp]");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp)), "ld1 {v13.d}[1], [sp]");

  COMPARE(Ld1(v0.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld1 {v0.b}[0], [x15], x0");
  COMPARE(Ld1(v1.V16B(), 1, MemOperand(x16, 1, PostIndex)),
          "ld1 {v1.b}[1], [x16], #1");
  COMPARE(Ld1(v2.V4H(), 2, MemOperand(x17, 2, PostIndex)),
          "ld1 {v2.h}[2], [x17], #2");
  COMPARE(Ld1(v3.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld1 {v3.h}[3], [x18], x1");
  COMPARE(Ld1(v4.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld1 {v4.s}[0], [x19], x2");
  COMPARE(Ld1(v5.V4S(), 1, MemOperand(x20, 4, PostIndex)),
          "ld1 {v5.s}[1], [x20], #4");
  COMPARE(Ld1(v6.V2D(), 0, MemOperand(x21, 8, PostIndex)),
          "ld1 {v6.d}[0], [x21], #8");
  COMPARE(Ld1(v7.B(), 7, MemOperand(x22, 1, PostIndex)),
          "ld1 {v7.b}[7], [x22], #1");
  COMPARE(Ld1(v8_.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld1 {v8.b}[15], [x23], x3");
  COMPARE(Ld1(v9.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld1 {v9.h}[3], [x24], x4");
  COMPARE(Ld1(v10.H(), 7, MemOperand(x25, 2, PostIndex)),
          "ld1 {v10.h}[7], [x25], #2");
  COMPARE(Ld1(v11.S(), 1, MemOperand(x26, 4, PostIndex)),
          "ld1 {v11.s}[1], [x26], #4");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld1 {v12.s}[3], [cp], x5");
  COMPARE(Ld1(v12.S(), 3, MemOperand(x27, 4, PostIndex)),
          "ld1 {v12.s}[3], [cp], #4");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld1 {v13.d}[1], [sp], x6");
  COMPARE(Ld1(v13.D(), 1, MemOperand(sp, 8, PostIndex)),
          "ld1 {v13.d}[1], [sp], #8");

  COMPARE(Ld2(v0.V8B(), v1.V8B(), 0, MemOperand(x15)),
          "ld2 {v0.b, v1.b}[0], [x15]");
  COMPARE(Ld2(v1.V16B(), v2.V16B(), 1, MemOperand(x16)),
          "ld2 {v1.b, v2.b}[1], [x16]");
  COMPARE(Ld2(v2.V4H(), v3.V4H(), 2, MemOperand(x17)),
          "ld2 {v2.h, v3.h}[2], [x17]");
  COMPARE(Ld2(v3.V8H(), v4.V8H(), 3, MemOperand(x18)),
          "ld2 {v3.h, v4.h}[3], [x18]");
  COMPARE(Ld2(v4.V2S(), v5.V2S(), 0, MemOperand(x19)),
          "ld2 {v4.s, v5.s}[0], [x19]");
  COMPARE(Ld2(v5.V4S(), v6.V4S(), 1, MemOperand(x20)),
          "ld2 {v5.s, v6.s}[1], [x20]");
  COMPARE(Ld2(v6.V2D(), v7.V2D(), 0, MemOperand(x21)),
          "ld2 {v6.d, v7.d}[0], [x21]");
  COMPARE(Ld2(v7.B(), v8_.B(), 7, MemOperand(x22)),
          "ld2 {v7.b, v8.b}[7], [x22]");
  COMPARE(Ld2(v8_.B(), v9.B(), 15, MemOperand(x23)),
          "ld2 {v8.b, v9.b}[15], [x23]");
  COMPARE(Ld2(v9.H(), v10.H(), 3, MemOperand(x24)),
          "ld2 {v9.h, v10.h}[3], [x24]");
  COMPARE(Ld2(v10.H(), v11.H(), 7, MemOperand(x25)),
          "ld2 {v10.h, v11.h}[7], [x25]");
  COMPARE(Ld2(v11.S(), v12.S(), 1, MemOperand(x26)),
          "ld2 {v11.s, v12.s}[1], [x26]");
  COMPARE(Ld2(v12.S(), v13.S(), 3, MemOperand(x27)),
          "ld2 {v12.s, v13.s}[3], [cp]");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp)),
          "ld2 {v13.d, v14.d}[1], [sp]");

  COMPARE(Ld2(v0.V8B(), v1.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld2 {v0.b, v1.b}[0], [x15], x0");
  COMPARE(Ld2(v1.V16B(), v2.V16B(), 1, MemOperand(x16, 2, PostIndex)),
          "ld2 {v1.b, v2.b}[1], [x16], #2");
  COMPARE(Ld2(v2.V4H(), v3.V4H(), 2, MemOperand(x17, 4, PostIndex)),
          "ld2 {v2.h, v3.h}[2], [x17], #4");
  COMPARE(Ld2(v3.V8H(), v4.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld2 {v3.h, v4.h}[3], [x18], x1");
  COMPARE(Ld2(v4.V2S(), v5.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld2 {v4.s, v5.s}[0], [x19], x2");
  COMPARE(Ld2(v5.V4S(), v6.V4S(), 1, MemOperand(x20, 8, PostIndex)),
          "ld2 {v5.s, v6.s}[1], [x20], #8");
  COMPARE(Ld2(v6.V2D(), v7.V2D(), 0, MemOperand(x21, 16, PostIndex)),
          "ld2 {v6.d, v7.d}[0], [x21], #16");
  COMPARE(Ld2(v7.B(), v8_.B(), 7, MemOperand(x22, 2, PostIndex)),
          "ld2 {v7.b, v8.b}[7], [x22], #2");
  COMPARE(Ld2(v8_.B(), v9.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld2 {v8.b, v9.b}[15], [x23], x3");
  COMPARE(Ld2(v9.H(), v10.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld2 {v9.h, v10.h}[3], [x24], x4");
  COMPARE(Ld2(v10.H(), v11.H(), 7, MemOperand(x25, 4, PostIndex)),
          "ld2 {v10.h, v11.h}[7], [x25], #4");
  COMPARE(Ld2(v11.S(), v12.S(), 1, MemOperand(x26, 8, PostIndex)),
          "ld2 {v11.s, v12.s}[1], [x26], #8");
  COMPARE(Ld2(v12.S(), v13.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld2 {v12.s, v13.s}[3], [cp], x5");
  COMPARE(Ld2(v11.S(), v12.S(), 3, MemOperand(x26, 8, PostIndex)),
          "ld2 {v11.s, v12.s}[3], [x26], #8");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld2 {v13.d, v14.d}[1], [sp], x6");
  COMPARE(Ld2(v13.D(), v14.D(), 1, MemOperand(sp, 16, PostIndex)),
          "ld2 {v13.d, v14.d}[1], [sp], #16");

  COMPARE(Ld3(v0.V8B(), v1.V8B(), v2.V8B(), 0, MemOperand(x15)),
          "ld3 {v0.b, v1.b, v2.b}[0], [x15]");
  COMPARE(Ld3(v1.V16B(), v2.V16B(), v3.V16B(), 1, MemOperand(x16)),
          "ld3 {v1.b, v2.b, v3.b}[1], [x16]");
  COMPARE(Ld3(v2.V4H(), v3.V4H(), v4.V4H(), 2, MemOperand(x17)),
          "ld3 {v2.h, v3.h, v4.h}[2], [x17]");
  COMPARE(Ld3(v3.V8H(), v4.V8H(), v5.V8H(), 3, MemOperand(x18)),
          "ld3 {v3.h, v4.h, v5.h}[3], [x18]");
  COMPARE(Ld3(v4.V2S(), v5.V2S(), v6.V2S(), 0, MemOperand(x19)),
          "ld3 {v4.s, v5.s, v6.s}[0], [x19]");
  COMPARE(Ld3(v5.V4S(), v6.V4S(), v7.V4S(), 1, MemOperand(x20)),
          "ld3 {v5.s, v6.s, v7.s}[1], [x20]");
  COMPARE(Ld3(v6.V2D(), v7.V2D(), v8_.V2D(), 0, MemOperand(x21)),
          "ld3 {v6.d, v7.d, v8.d}[0], [x21]");
  COMPARE(Ld3(v7.B(), v8_.B(), v9.B(), 7, MemOperand(x22)),
          "ld3 {v7.b, v8.b, v9.b}[7], [x22]");
  COMPARE(Ld3(v8_.B(), v9.B(), v10.B(), 15, MemOperand(x23)),
          "ld3 {v8.b, v9.b, v10.b}[15], [x23]");
  COMPARE(Ld3(v9.H(), v10.H(), v11.H(), 3, MemOperand(x24)),
          "ld3 {v9.h, v10.h, v11.h}[3], [x24]");
  COMPARE(Ld3(v10.H(), v11.H(), v12.H(), 7, MemOperand(x25)),
          "ld3 {v10.h, v11.h, v12.h}[7], [x25]");
  COMPARE(Ld3(v11.S(), v12.S(), v13.S(), 1, MemOperand(x26)),
          "ld3 {v11.s, v12.s, v13.s}[1], [x26]");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp]");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp]");

  COMPARE(Ld3(v0.V8B(), v1.V8B(), v2.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "ld3 {v0.b, v1.b, v2.b}[0], [x15], x0");
  COMPARE(
      Ld3(v1.V16B(), v2.V16B(), v3.V16B(), 1, MemOperand(x16, 3, PostIndex)),
      "ld3 {v1.b, v2.b, v3.b}[1], [x16], #3");
  COMPARE(Ld3(v2.V4H(), v3.V4H(), v4.V4H(), 2, MemOperand(x17, 6, PostIndex)),
          "ld3 {v2.h, v3.h, v4.h}[2], [x17], #6");
  COMPARE(Ld3(v3.V8H(), v4.V8H(), v5.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "ld3 {v3.h, v4.h, v5.h}[3], [x18], x1");
  COMPARE(Ld3(v4.V2S(), v5.V2S(), v6.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "ld3 {v4.s, v5.s, v6.s}[0], [x19], x2");
  COMPARE(Ld3(v5.V4S(), v6.V4S(), v7.V4S(), 1, MemOperand(x20, 12, PostIndex)),
          "ld3 {v5.s, v6.s, v7.s}[1], [x20], #12");
  COMPARE(Ld3(v6.V2D(), v7.V2D(), v8_.V2D(), 0, MemOperand(x21, 24, PostIndex)),
          "ld3 {v6.d, v7.d, v8.d}[0], [x21], #24");
  COMPARE(Ld3(v7.B(), v8_.B(), v9.B(), 7, MemOperand(x22, 3, PostIndex)),
          "ld3 {v7.b, v8.b, v9.b}[7], [x22], #3");
  COMPARE(Ld3(v8_.B(), v9.B(), v10.B(), 15, MemOperand(x23, x3, PostIndex)),
          "ld3 {v8.b, v9.b, v10.b}[15], [x23], x3");
  COMPARE(Ld3(v9.H(), v10.H(), v11.H(), 3, MemOperand(x24, x4, PostIndex)),
          "ld3 {v9.h, v10.h, v11.h}[3], [x24], x4");
  COMPARE(Ld3(v10.H(), v11.H(), v12.H(), 7, MemOperand(x25, 6, PostIndex)),
          "ld3 {v10.h, v11.h, v12.h}[7], [x25], #6");
  COMPARE(Ld3(v11.S(), v12.S(), v13.S(), 1, MemOperand(x26, 12, PostIndex)),
          "ld3 {v11.s, v12.s, v13.s}[1], [x26], #12");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27, x5, PostIndex)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp], x5");
  COMPARE(Ld3(v12.S(), v13.S(), v14.S(), 3, MemOperand(x27, 12, PostIndex)),
          "ld3 {v12.s, v13.s, v14.s}[3], [cp], #12");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp, x6, PostIndex)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp], x6");
  COMPARE(Ld3(v13.D(), v14.D(), v15.D(), 1, MemOperand(sp, 24, PostIndex)),
          "ld3 {v13.d, v14.d, v15.d}[1], [sp], #24");

  COMPARE(Ld4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), 0, MemOperand(x15)),
          "ld4 {v0.b, v1.b, v2.b, v3.b}[0], [x15]");
  COMPARE(Ld4(v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), 1, MemOperand(x16)),
          "ld4 {v1.b, v2.b, v3.b, v4.b}[1], [x16]");
  COMPARE(Ld4(v2.V4H(), v3.V4H(), v4.V4H(), v5.V4H(), 2, MemOperand(x17)),
          "ld4 {v2.h, v3.h, v4.h, v5.h}[2], [x17]");
  COMPARE(Ld4(v3.V8H(), v4.V8H(), v5.V8H(), v6.V8H(), 3, MemOperand(x18)),
          "ld4 {v3.h, v4.h, v5.h, v6.h}[3], [x18]");
  COMPARE(Ld4(v4.V2S(), v5.V2S(), v6.V2S(), v7.V2S(), 0, MemOperand(x19)),
          "ld4 {v4.s, v5.s, v6.s, v7.s}[0], [x19]");
  COMPARE(Ld4(v5.V4S(), v6.V4S(), v7.V4S(), v8_.V4S(), 1, MemOperand(x20)),
          "ld4 {v5.s, v6.s, v7.s, v8.s}[1], [x20]");
  COMPARE(Ld4(v6.V2D(), v7.V2D(), v8_.V2D(), v9.V2D(), 0, MemOperand(x21)),
          "ld4 {v6.d, v7.d, v8.d, v9.d}[0], [x21]");
  COMPARE(Ld4(v7.B(), v8_.B(), v9.B(), v10.B(), 7, MemOperand(x22)),
          "ld4 {v7.b, v8.b, v9.b, v10.b}[7], [x22]");
  COMPARE(Ld4(v8_.B(), v9.B(), v10.B(), v11.B(), 15, MemOperand(x23)),
          "ld4 {v8.b, v9.b, v10.b, v11.b}[15], [x23]");
  COMPARE(Ld4(v9.H(), v10.H(), v11.H(), v12.H(), 3, MemOperand(x24)),
          "ld4 {v9.h, v10.h, v11.h, v12.h}[3], [x24]");
  COMPARE(Ld4(v10.H(), v11.H(), v12.H(), v13.H(), 7, MemOperand(x25)),
          "ld4 {v10.h, v11.h, v12.h, v13.h}[7], [x25]");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 1, MemOperand(x26)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[1], [x26]");
  COMPARE(Ld4(v12.S(), v13.S(), v14.S(), v15.S(), 3, MemOperand(x27)),
          "ld4 {v12.s, v13.s, v14.s, v15.s}[3], [cp]");
  COMPARE(Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp)),
          "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp]");

  COMPARE(Ld4(v0.V8B(), v1.V8B(), v2.V8B(), v3.V8B(), 0,
              MemOperand(x15, x0, PostIndex)),
          "ld4 {v0.b, v1.b, v2.b, v3.b}[0], [x15], x0");
  COMPARE(Ld4(v1.V16B(), v2.V16B(), v3.V16B(), v4.V16B(), 1,
              MemOperand(x16, 4, PostIndex)),
          "ld4 {v1.b, v2.b, v3.b, v4.b}[1], [x16], #4");
  COMPARE(Ld4(v2.V4H(), v3.V4H(), v4.V4H(), v5.V4H(), 2,
              MemOperand(x17, 8, PostIndex)),
          "ld4 {v2.h, v3.h, v4.h, v5.h}[2], [x17], #8");
  COMPARE(Ld4(v3.V8H(), v4.V8H(), v5.V8H(), v6.V8H(), 3,
              MemOperand(x18, x1, PostIndex)),
          "ld4 {v3.h, v4.h, v5.h, v6.h}[3], [x18], x1");
  COMPARE(Ld4(v4.V2S(), v5.V2S(), v6.V2S(), v7.V2S(), 0,
              MemOperand(x19, x2, PostIndex)),
          "ld4 {v4.s, v5.s, v6.s, v7.s}[0], [x19], x2");
  COMPARE(Ld4(v5.V4S(), v6.V4S(), v7.V4S(), v8_.V4S(), 1,
              MemOperand(x20, 16, PostIndex)),
          "ld4 {v5.s, v6.s, v7.s, v8.s}[1], [x20], #16");
  COMPARE(Ld4(v6.V2D(), v7.V2D(), v8_.V2D(), v9.V2D(), 0,
              MemOperand(x21, 32, PostIndex)),
          "ld4 {v6.d, v7.d, v8.d, v9.d}[0], [x21], #32");
  COMPARE(
      Ld4(v7.B(), v8_.B(), v9.B(), v10.B(), 7, MemOperand(x22, 4, PostIndex)),
      "ld4 {v7.b, v8.b, v9.b, v10.b}[7], [x22], #4");
  COMPARE(Ld4(v8_.B(), v9.B(), v10.B(), v11.B(), 15,
              MemOperand(x23, x3, PostIndex)),
          "ld4 {v8.b, v9.b, v10.b, v11.b}[15], [x23], x3");
  COMPARE(
      Ld4(v9.H(), v10.H(), v11.H(), v12.H(), 3, MemOperand(x24, x4, PostIndex)),
      "ld4 {v9.h, v10.h, v11.h, v12.h}[3], [x24], x4");
  COMPARE(
      Ld4(v10.H(), v11.H(), v12.H(), v13.H(), 7, MemOperand(x25, 8, PostIndex)),
      "ld4 {v10.h, v11.h, v12.h, v13.h}[7], [x25], #8");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 1,
              MemOperand(x26, 16, PostIndex)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[1], [x26], #16");
  COMPARE(Ld4(v12.S(), v13.S(), v14.S(), v15.S(), 3,
              MemOperand(x27, x5, PostIndex)),
          "ld4 {v12.s, v13.s, v14.s, v15.s}[3], [cp], x5");
  COMPARE(Ld4(v11.S(), v12.S(), v13.S(), v14.S(), 3,
              MemOperand(x26, 16, PostIndex)),
          "ld4 {v11.s, v12.s, v13.s, v14.s}[3], [x26], #16");
  COMPARE(
      Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp, x6, PostIndex)),
      "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], x6");
  COMPARE(
      Ld4(v13.D(), v14.D(), v15.D(), v16.D(), 1, MemOperand(sp, 32, PostIndex)),
      "ld4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], #32");

  COMPARE(St1(v0.V8B(), 0, MemOperand(x15)), "st1 {v0.b}[0], [x15]");
  COMPARE(St1(v1.V16B(), 1, MemOperand(x16)), "st1 {v1.b}[1], [x16]");
  COMPARE(St1(v2.V4H(), 2, MemOperand(x17)), "st1 {v2.h}[2], [x17]");
  COMPARE(St1(v3.V8H(), 3, MemOperand(x18)), "st1 {v3.h}[3], [x18]");
  COMPARE(St1(v4.V2S(), 0, MemOperand(x19)), "st1 {v4.s}[0], [x19]");
  COMPARE(St1(v5.V4S(), 1, MemOperand(x20)), "st1 {v5.s}[1], [x20]");
  COMPARE(St1(v6.V2D(), 0, MemOperand(x21)), "st1 {v6.d}[0], [x21]");
  COMPARE(St1(v7.B(), 7, MemOperand(x22)), "st1 {v7.b}[7], [x22]");
  COMPARE(St1(v8_.B(), 15, MemOperand(x23)), "st1 {v8.b}[15], [x23]");
  COMPARE(St1(v9.H(), 3, MemOperand(x24)), "st1 {v9.h}[3], [x24]");
  COMPARE(St1(v10.H(), 7, MemOperand(x25)), "st1 {v10.h}[7], [x25]");
  COMPARE(St1(v11.S(), 1, MemOperand(x26)), "st1 {v11.s}[1], [x26]");
  COMPARE(St1(v12.S(), 3, MemOperand(x27)), "st1 {v12.s}[3], [cp]");
  COMPARE(St1(v13.D(), 1, MemOperand(sp)), "st1 {v13.d}[1], [sp]");

  COMPARE(St1(v0.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "st1 {v0.b}[0], [x15], x0");
  COMPARE(St1(v1.V16B(), 1, MemOperand(x16, 1, PostIndex)),
          "st1 {v1.b}[1], [x16], #1");
  COMPARE(St1(v2.V4H(), 2, MemOperand(x17, 2, PostIndex)),
          "st1 {v2.h}[2], [x17], #2");
  COMPARE(St1(v3.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "st1 {v3.h}[3], [x18], x1");
  COMPARE(St1(v4.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "st1 {v4.s}[0], [x19], x2");
  COMPARE(St1(v5.V4S(), 1
"""


```