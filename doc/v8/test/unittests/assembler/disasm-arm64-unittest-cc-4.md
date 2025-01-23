Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This code is a unit test file for the ARM64 disassembler in the V8 JavaScript engine.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The filename `disasm-arm64-unittest.cc` and the structure of the code (using `TEST_F`) clearly indicate that this is a unit test file specifically for the ARM64 disassembler. The tests aim to verify that the disassembler correctly translates machine code (represented by the `dci` function or constructed using `masm.`) into human-readable assembly instructions.

2. **Analyze the Test Structure:** The code is organized into multiple `TEST_F` blocks. Each block focuses on testing a specific category of ARM64 instructions. Keywords like "neon_load_store_lane", "neon_load_all_lanes", "neon_3same", "neon_fp_3same", and "neon_scalar_3same" give clues about the instruction types being tested (NEON/SIMD instructions).

3. **Examine Individual Tests:**  Within each `TEST_F`, the `COMPARE` macro is the key. It takes an assembly instruction (constructed programmatically or represented by a hexadecimal value passed to `dci`) and compares the output of the disassembler for that instruction against an expected string representation.

4. **Categorize the Tested Instructions:**  The tests cover various aspects of ARM64 NEON instructions:
    * **Load and Store with Lane:** Instructions like `St1`, `St2`, `St3`, `St4` and their corresponding load instructions (`Ld1`, `Ld2`, `Ld3`, `Ld4`) targeting specific lanes within NEON registers.
    * **Load All Lanes (Broadcast):** Instructions like `Ld1r`, `Ld2r`, `Ld3r`, `Ld4r` that load the same value into all lanes of a NEON register.
    * **Three-Operand Instructions:**  A wide range of arithmetic, logical, and comparison NEON instructions taking three register operands (e.g., `add v0.8b, v1.8b, v2.8b`). These are tested for both integer and floating-point operations.
    * **Scalar Instructions:** NEON instructions operating on single elements within a register.

5. **Address Specific Questions:**

    * **File Extension:** The prompt asks about `.tq`. The file ends in `.cc`, so it's a C++ source file, not a Torque file.
    * **Relationship to JavaScript:**  This code directly relates to V8's ability to execute JavaScript. V8 compiles JavaScript into machine code, including ARM64 instructions. The disassembler is used for debugging, profiling, and code inspection within V8. A simple JavaScript example demonstrating the *use* of SIMD features (which these instructions implement) would involve array manipulations.
    * **Code Logic and I/O:** The tests have implicit inputs (the ARM64 instructions) and expected outputs (the disassembled strings). For example, `St1(v0.B(), 0, MemOperand(x15, PostIndex))` is the input, and `"st1 {v0.b}[0], [x15]"` is the expected output.
    * **Common Programming Errors:**  While the *test* code itself doesn't directly illustrate user programming errors, the *instructions* being tested are fundamental to efficient SIMD programming. Common errors include incorrect memory addressing, using the wrong data types, or misunderstanding lane indexing.
    * **Overall Function:** The file tests the correctness of the ARM64 disassembler in V8, particularly its handling of NEON instructions.

6. **Structure the Summary:** Organize the findings into clear points covering the main functionalities and addressing the user's specific questions. Use the provided keywords from the code to structure the summary (e.g., "NEON load/store instructions", "Three-operand NEON instructions").

7. **Refine and Review:** Read through the summary to ensure clarity, accuracy, and completeness. Make sure all aspects of the prompt have been addressed. For instance, initially, I might just say "tests NEON instructions," but refining it to specify different categories of NEON instructions (load/store, three-operand, scalar) makes the summary more informative.
这是目录为`v8/test/unittests/assembler/disasm-arm64-unittest.cc`的 V8 源代码文件，其主要功能是 **测试 ARM64 架构的反汇编器 (disassembler) 的正确性**。

**功能归纳:**

这个文件的核心功能是验证 V8 引擎中用于将 ARM64 机器码指令转换回可读汇编代码的模块（反汇编器）是否工作正常。它通过生成各种 ARM64 指令，然后使用反汇编器将其转换回汇编字符串，并与预期的字符串进行比较，从而实现测试。

**详细功能列表:**

* **测试 NEON 向量指令的反汇编:** 文件中包含了大量针对 NEON (Advanced SIMD) 指令的测试用例。NEON 是一种用于并行处理数据的 SIMD 指令集，在 ARM 架构上被广泛用于加速多媒体和科学计算等任务。
    * **测试加载和存储单个元素的指令 (Load/Store Lane):**  例如 `St1`, `St2`, `St3`, `St4` 以及对应的 `Ld1`, `Ld2`, `Ld3`, `Ld4` 指令，用于测试将 NEON 寄存器中的特定元素存储到内存，或者从内存加载到 NEON 寄存器的特定元素。
    * **测试加载所有元素的指令 (Load All Lanes):** 例如 `Ld1r`, `Ld2r`, `Ld3r`, `Ld4r` 指令，用于测试将内存中的单个值复制到 NEON 寄存器的所有元素。
    * **测试三个操作数的 NEON 指令:**  例如 `Cmeq`, `Cmge`, `Cmgt`, `Add`, `Sub`, `Mul`, `Uqadd`, `Sqadd`, `Fadd`, `Fsub`, `Fmul` 等，用于测试涉及三个 NEON 寄存器的算术、逻辑和比较操作。这些测试覆盖了整数和浮点数操作。
    * **测试 NEON 标量指令:** 测试了对 NEON 寄存器中的单个标量元素进行操作的指令，例如 `Add`, `Sub`, `Cmeq`, `Cmge`, `Frecps`, `Frsqrts` 等。
* **测试未分配的指令:**  文件中包含了一些测试用例，用于检查反汇编器对于某些特定的指令编码是否能够正确地识别为“未分配”或无效的指令。这有助于确保反汇编器不会错误地解析未知的指令。
* **使用 `COMPARE` 宏进行断言:**  文件中大量使用了 `COMPARE` 宏，这个宏会调用反汇编器将生成的机器码指令转换为字符串，并将其与预期的字符串进行比较。如果两者不一致，则测试失败。
* **使用 `SET_UP_MASM()` 和 `CLEANUP()`:** 这些宏可能用于设置和清理汇编器环境，以便生成用于测试的机器码。
* **组织成不同的测试用例 (`TEST_F`)**:  代码被组织成多个独立的测试用例，每个测试用例针对一组相关的指令或特定的场景进行测试。

**关于文件类型和与 JavaScript 的关系:**

* **`.tq` 文件:**  `v8/test/unittests/assembler/disasm-arm64-unittest.cc` 的确是以 `.cc` 结尾，表明它是一个 **C++ 源文件**。如果文件名以 `.tq` 结尾，那才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。
* **与 JavaScript 的关系:**  尽管这个文件本身是 C++ 代码，用于测试底层的反汇编功能，但它与 JavaScript 的执行密切相关。V8 引擎负责执行 JavaScript 代码，其中一个关键步骤是将 JavaScript 代码编译成机器码，包括 ARM64 指令 (在 ARM64 架构的机器上)。反汇编器在 V8 中有多种用途，例如：
    * **调试:**  在开发和调试 V8 引擎本身时，反汇编器可以帮助开发者理解生成的机器码，排查编译错误或性能问题。
    * **性能分析:**  通过反汇编生成的代码，可以分析其效率，找出潜在的优化点。
    * **JIT 代码优化:**  V8 的即时编译器 (JIT) 会动态地生成和优化代码。反汇编器可以帮助理解 JIT 优化后的代码。

**JavaScript 示例 (体现 NEON 指令可能加速的场景):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 NEON 指令可以显著加速 JavaScript 中的某些操作，尤其是在处理数组或执行数值计算时。例如，考虑一个简单的数组加法：

```javascript
function addArrays(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] + b[i]);
  }
  return result;
}

const array1 = [1, 2, 3, 4, 5, 6, 7, 8];
const array2 = [9, 10, 11, 12, 13, 14, 15, 16];
const sum = addArrays(array1, array2);
console.log(sum); // 输出: [10, 12, 14, 16, 18, 20, 22, 24]
```

在 V8 引擎的底层，如果启用了 NEON 支持，JIT 编译器可能会将循环中的加法操作优化为使用 NEON 指令，例如 `add v0.8b, v1.8b, v2.8b` (如果数组元素是 8 位整数)，从而一次性处理多个数组元素，提高执行效率。

**代码逻辑推理 (假设输入与输出):**

假设 `masm` 是一个汇编器对象，`v0`, `v1`, `v2`, `x15` 是寄存器对象。

**假设输入:**

```c++
  MacroAssembler masm;
  Register x15 = r1;
  // ... 初始化 v0, v1, v2 等 NEON 寄存器
  NEONRegister v0 = q0;
  NEONRegister v1 = q1;
  NEONRegister v2 = q2;

  masm.St1(v0.B(), 0, MemOperand(x15, Assembler::PostIndex));
```

**预期输出 (反汇编后的字符串):**

```
"st1 {v0.b}[0], [r1]+"
```

**解释:**

`St1(v0.B(), 0, MemOperand(x15, Assembler::PostIndex))` 这段代码生成了一条 ARM64 的 `ST1` 指令，其含义是将 NEON 寄存器 `v0` 的第 0 个字节元素存储到内存地址 `x15` 指向的位置，并且在存储后将 `x15` 的值增加元素的大小 (这里是 1 字节)。反汇编器应该能够将这条机器码指令转换回 `st1 {v0.b}[0], [r1]+` 这样的汇编字符串 (假设 `x15` 对应寄存器 `r1`)。

**涉及用户常见的编程错误 (与 NEON 指令使用相关):**

虽然这个测试文件本身不是用户代码，但它测试的指令是用户在使用 NEON 进行编程时会用到的。一些常见的编程错误包括：

1. **内存对齐错误:** NEON 指令通常对内存对齐有要求。例如，加载双字 (64 位) 数据时，内存地址需要是 8 字节对齐的。如果内存未正确对齐，可能导致程序崩溃或性能下降。
    ```c++
    // 错误示例：假设 x1 指向的地址不是 8 字节对齐的
    // masm.Ld1(v0.D(), MemOperand(x1));
    ```

2. **访问越界:**  尝试访问 NEON 寄存器中不存在的元素或超出数组边界的内存。
    ```c++
    // 错误示例：v0 是 V8B (8 个字节)，尝试访问索引 10
    // masm.St1(v0.B(), 10, MemOperand(x1));
    ```

3. **数据类型不匹配:**  在 NEON 指令中使用了错误的数据类型。例如，尝试将单精度浮点数加载到需要双精度浮点数的寄存器中。
    ```c++
    // 错误示例：尝试将单精度数据加载到双精度寄存器
    // masm.Ld1(v0.D(), MemOperand(x1)); // 假设内存中是单精度数据
    ```

4. **不正确的寄存器使用:**  错误地使用了 NEON 寄存器，例如将结果写入了错误的寄存器，导致后续计算出错。

5. **对指令的误解:**  不完全理解 NEON 指令的功能和限制，导致使用了错误的指令来完成任务。

总结来说，`v8/test/unittests/assembler/disasm-arm64-unittest.cc` 是 V8 引擎中一个至关重要的测试文件，它专门用于验证 ARM64 反汇编器的正确性，确保 V8 能够准确地将机器码指令转换回可读的汇编代码，这对于 V8 的调试、性能分析和 JIT 代码优化至关重要。

### 提示词
```
这是目录为v8/test/unittests/assembler/disasm-arm64-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/assembler/disasm-arm64-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
, MemOperand(x20, 4, PostIndex)),
          "st1 {v5.s}[1], [x20], #4");
  COMPARE(St1(v6.V2D(), 0, MemOperand(x21, 8, PostIndex)),
          "st1 {v6.d}[0], [x21], #8");
  COMPARE(St1(v7.B(), 7, MemOperand(x22, 1, PostIndex)),
          "st1 {v7.b}[7], [x22], #1");
  COMPARE(St1(v8_.B(), 15, MemOperand(x23, x3, PostIndex)),
          "st1 {v8.b}[15], [x23], x3");
  COMPARE(St1(v9.H(), 3, MemOperand(x24, x4, PostIndex)),
          "st1 {v9.h}[3], [x24], x4");
  COMPARE(St1(v10.H(), 7, MemOperand(x25, 2, PostIndex)),
          "st1 {v10.h}[7], [x25], #2");
  COMPARE(St1(v11.S(), 1, MemOperand(x26, 4, PostIndex)),
          "st1 {v11.s}[1], [x26], #4");
  COMPARE(St1(v12.S(), 3, MemOperand(x27, x5, PostIndex)),
          "st1 {v12.s}[3], [cp], x5");
  COMPARE(St1(v13.D(), 1, MemOperand(sp, x6, PostIndex)),
          "st1 {v13.d}[1], [sp], x6");
  COMPARE(St2(v0.V8B(), v1.V8B(), 0, MemOperand(x15, x0, PostIndex)),
          "st2 {v0.b, v1.b}[0], [x15], x0");
  COMPARE(St2(v1.V16B(), v2.V16B(), 1, MemOperand(x16, 2, PostIndex)),
          "st2 {v1.b, v2.b}[1], [x16], #2");
  COMPARE(St2(v2.V4H(), v3.V4H(), 2, MemOperand(x17, 4, PostIndex)),
          "st2 {v2.h, v3.h}[2], [x17], #4");
  COMPARE(St2(v3.V8H(), v4.V8H(), 3, MemOperand(x18, x1, PostIndex)),
          "st2 {v3.h, v4.h}[3], [x18], x1");
  COMPARE(St2(v4.V2S(), v5.V2S(), 0, MemOperand(x19, x2, PostIndex)),
          "st2 {v4.s, v5.s}[0], [x19], x2");
  COMPARE(St2(v5.V4S(), v6.V4S(), 1, MemOperand(x20, 8, PostIndex)),
          "st2 {v5.s, v6.s}[1], [x20], #8");
  COMPARE(St2(v6.V2D(), v7.V2D(), 0, MemOperand(x21, 16, PostIndex)),
          "st2 {v6.d, v7.d}[0], [x21], #16");
  COMPARE(St2(v7.B(), v8_.B(), 7, MemOperand(x22, 2, PostIndex)),
          "st2 {v7.b, v8.b}[7], [x22], #2");
  COMPARE(St2(v8_.B(), v9.B(), 15, MemOperand(x23, x3, PostIndex)),
          "st2 {v8.b, v9.b}[15], [x23], x3");
  COMPARE(St2(v9.H(), v10.H(), 3, MemOperand(x24, x4, PostIndex)),
          "st2 {v9.h, v10.h}[3], [x24], x4");
  COMPARE(St2(v10.H(), v11.H(), 7, MemOperand(x25, 4, PostIndex)),
          "st2 {v10.h, v11.h}[7], [x25], #4");
  COMPARE(St2(v11.S(), v12.S(), 1, MemOperand(x26, 8, PostIndex)),
          "st2 {v11.s, v12.s}[1], [x26], #8");
  COMPARE(St2(v12.S(), v13.S(), 3, MemOperand(x27, x5, PostIndex)),
          "st2 {v12.s, v13.s}[3], [cp], x5");
  COMPARE(St2(v13.D(), v14.D(), 1, MemOperand(sp, x6, PostIndex)),
          "st2 {v13.d, v14.d}[1], [sp], x6");
  COMPARE(St3(VLIST3(v0.V8B()), 0, MemOperand(x15, x0, PostIndex)),
          "st3 {v0.b, v1.b, v2.b}[0], [x15], x0");
  COMPARE(St3(VLIST3(v1.V16B()), 1, MemOperand(x16, 3, PostIndex)),
          "st3 {v1.b, v2.b, v3.b}[1], [x16], #3");
  COMPARE(St3(VLIST3(v2.V4H()), 2, MemOperand(x17, 6, PostIndex)),
          "st3 {v2.h, v3.h, v4.h}[2], [x17], #6");
  COMPARE(St3(VLIST3(v3.V8H()), 3, MemOperand(x18, x1, PostIndex)),
          "st3 {v3.h, v4.h, v5.h}[3], [x18], x1");
  COMPARE(St3(VLIST3(v4.V2S()), 0, MemOperand(x19, x2, PostIndex)),
          "st3 {v4.s, v5.s, v6.s}[0], [x19], x2");
  COMPARE(St3(VLIST3(v5.V4S()), 1, MemOperand(x20, 12, PostIndex)),
          "st3 {v5.s, v6.s, v7.s}[1], [x20], #12");
  COMPARE(St3(VLIST3(v6.V2D()), 0, MemOperand(x21, 24, PostIndex)),
          "st3 {v6.d, v7.d, v8.d}[0], [x21], #24");
  COMPARE(St3(VLIST3(v7.B()), 7, MemOperand(x22, 3, PostIndex)),
          "st3 {v7.b, v8.b, v9.b}[7], [x22], #3");
  COMPARE(St3(VLIST3(v8_.B()), 15, MemOperand(x23, x3, PostIndex)),
          "st3 {v8.b, v9.b, v10.b}[15], [x23], x3");
  COMPARE(St3(VLIST3(v9.H()), 3, MemOperand(x24, x4, PostIndex)),
          "st3 {v9.h, v10.h, v11.h}[3], [x24], x4");
  COMPARE(St3(VLIST3(v10.H()), 7, MemOperand(x25, 6, PostIndex)),
          "st3 {v10.h, v11.h, v12.h}[7], [x25], #6");
  COMPARE(St3(VLIST3(v11.S()), 1, MemOperand(x26, 12, PostIndex)),
          "st3 {v11.s, v12.s, v13.s}[1], [x26], #12");
  COMPARE(St3(VLIST3(v12.S()), 3, MemOperand(x27, x5, PostIndex)),
          "st3 {v12.s, v13.s, v14.s}[3], [cp], x5");
  COMPARE(St3(VLIST3(v13.D()), 1, MemOperand(sp, x6, PostIndex)),
          "st3 {v13.d, v14.d, v15.d}[1], [sp], x6");

  COMPARE(St4(VLIST4(v0.V8B()), 0, MemOperand(x15, x0, PostIndex)),
          "st4 {v0.b, v1.b, v2.b, v3.b}[0], [x15], x0");
  COMPARE(St4(VLIST4(v1.V16B()), 1, MemOperand(x16, 4, PostIndex)),
          "st4 {v1.b, v2.b, v3.b, v4.b}[1], [x16], #4");
  COMPARE(St4(VLIST4(v2.V4H()), 2, MemOperand(x17, 8, PostIndex)),
          "st4 {v2.h, v3.h, v4.h, v5.h}[2], [x17], #8");
  COMPARE(St4(VLIST4(v3.V8H()), 3, MemOperand(x18, x1, PostIndex)),
          "st4 {v3.h, v4.h, v5.h, v6.h}[3], [x18], x1");
  COMPARE(St4(VLIST4(v4.V2S()), 0, MemOperand(x19, x2, PostIndex)),
          "st4 {v4.s, v5.s, v6.s, v7.s}[0], [x19], x2");
  COMPARE(St4(VLIST4(v5.V4S()), 1, MemOperand(x20, 16, PostIndex)),
          "st4 {v5.s, v6.s, v7.s, v8.s}[1], [x20], #16");
  COMPARE(St4(VLIST4(v6.V2D()), 0, MemOperand(x21, 32, PostIndex)),
          "st4 {v6.d, v7.d, v8.d, v9.d}[0], [x21], #32");
  COMPARE(St4(VLIST4(v7.B()), 7, MemOperand(x22, 4, PostIndex)),
          "st4 {v7.b, v8.b, v9.b, v10.b}[7], [x22], #4");
  COMPARE(St4(VLIST4(v8_.B()), 15, MemOperand(x23, x3, PostIndex)),
          "st4 {v8.b, v9.b, v10.b, v11.b}[15], [x23], x3");
  COMPARE(St4(VLIST4(v9.H()), 3, MemOperand(x24, x4, PostIndex)),
          "st4 {v9.h, v10.h, v11.h, v12.h}[3], [x24], x4");
  COMPARE(St4(VLIST4(v10.H()), 7, MemOperand(x25, 8, PostIndex)),
          "st4 {v10.h, v11.h, v12.h, v13.h}[7], [x25], #8");
  COMPARE(St4(VLIST4(v11.S()), 1, MemOperand(x26, 16, PostIndex)),
          "st4 {v11.s, v12.s, v13.s, v14.s}[1], [x26], #16");
  COMPARE(St4(VLIST4(v12.S()), 3, MemOperand(x27, x5, PostIndex)),
          "st4 {v12.s, v13.s, v14.s, v15.s}[3], [cp], x5");
  COMPARE(St4(VLIST4(v13.D()), 1, MemOperand(sp, x6, PostIndex)),
          "st4 {v13.d, v14.d, v15.d, v16.d}[1], [sp], x6");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_store_lane_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreSingleStruct)";
  // LD1 (single structure) (no offset)
  COMPARE(dci(0x0d404400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d408800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d409400), expected);  // .d, size<0> = 1, S = 1
  // LD2 (single structure) (no offset)
  COMPARE(dci(0x0d604400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d608800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d609400), expected);  // .d, size<0> = 1, S = 1
  // LD3 (single structure) (no offset)
  COMPARE(dci(0x0d406400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d40a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d40b400), expected);  // .d, size<0> = 1, S = 1
  // LD4 (single structure) (no offset)
  COMPARE(dci(0x0d606400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d60a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d60b400), expected);  // .d, size<0> = 1, S = 1
  // ST1 (single structure) (no offset)
  COMPARE(dci(0x0d004400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d008800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d009400), expected);  // .d, size<0> = 1, S = 1
  // ST2 (single structure) (no offset)
  COMPARE(dci(0x0d204400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d208800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d209400), expected);  // .d, size<0> = 1, S = 1
  // ST3 (single structure) (no offset)
  COMPARE(dci(0x0d006400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d00a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d00b400), expected);  // .d, size<0> = 1, S = 1
  // ST4 (single structure) (no offset)
  COMPARE(dci(0x0d206400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d20a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d20b400), expected);  // .d, size<0> = 1, S = 1

  expected = "unallocated (NEONLoadStoreSingleStructPostIndex)";
  // LD1 (single structure) (post index)
  COMPARE(dci(0x0dc04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0dc08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0dc09400), expected);  // .d, size<0> = 1, S = 1
  // LD2 (single structure) (post index)
  COMPARE(dci(0x0de04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0de08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0de09400), expected);  // .d, size<0> = 1, S = 1
  // LD3 (single structure) (post index)
  COMPARE(dci(0x0dc06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0dc0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0dc0b400), expected);  // .d, size<0> = 1, S = 1
  // LD4 (single structure) (post index)
  COMPARE(dci(0x0de06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0de0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0de0b400), expected);  // .d, size<0> = 1, S = 1
  // ST1 (single structure) (post index)
  COMPARE(dci(0x0d804400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d808800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d809400), expected);  // .d, size<0> = 1, S = 1
  // ST2 (single structure) (post index)
  COMPARE(dci(0x0da04400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0da08800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0da09400), expected);  // .d, size<0> = 1, S = 1
  // ST3 (single structure) (post index)
  COMPARE(dci(0x0d806400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0d80a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0d80b400), expected);  // .d, size<0> = 1, S = 1
  // ST4 (single structure) (post index)
  COMPARE(dci(0x0da06400), expected);  // .h, size<0> = 1
  COMPARE(dci(0x0da0a800), expected);  // .s, size<1> = 1
  COMPARE(dci(0x0da0b400), expected);  // .d, size<0> = 1, S = 1

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_all_lanes) {
  SET_UP_MASM();

  COMPARE(Ld1r(v14.V8B(), MemOperand(x0)), "ld1r {v14.8b}, [x0]");
  COMPARE(Ld1r(v15.V16B(), MemOperand(x1)), "ld1r {v15.16b}, [x1]");
  COMPARE(Ld1r(v16.V4H(), MemOperand(x2)), "ld1r {v16.4h}, [x2]");
  COMPARE(Ld1r(v17.V8H(), MemOperand(x3)), "ld1r {v17.8h}, [x3]");
  COMPARE(Ld1r(v18.V2S(), MemOperand(x4)), "ld1r {v18.2s}, [x4]");
  COMPARE(Ld1r(v19.V4S(), MemOperand(x5)), "ld1r {v19.4s}, [x5]");
  COMPARE(Ld1r(v20.V2D(), MemOperand(sp)), "ld1r {v20.2d}, [sp]");
  COMPARE(Ld1r(v21.V1D(), MemOperand(x30)), "ld1r {v21.1d}, [lr]");

  COMPARE(Ld1r(v22.V8B(), MemOperand(x6, 1, PostIndex)),
          "ld1r {v22.8b}, [x6], #1");
  COMPARE(Ld1r(v23.V16B(), MemOperand(x7, x16, PostIndex)),
          "ld1r {v23.16b}, [x7], x16");
  COMPARE(Ld1r(v24.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld1r {v24.4h}, [x8], x17");
  COMPARE(Ld1r(v25.V8H(), MemOperand(x9, 2, PostIndex)),
          "ld1r {v25.8h}, [x9], #2");
  COMPARE(Ld1r(v26.V2S(), MemOperand(x10, 4, PostIndex)),
          "ld1r {v26.2s}, [x10], #4");
  COMPARE(Ld1r(v27.V4S(), MemOperand(x11, x18, PostIndex)),
          "ld1r {v27.4s}, [x11], x18");
  COMPARE(Ld1r(v28.V2D(), MemOperand(x12, 8, PostIndex)),
          "ld1r {v28.2d}, [x12], #8");
  COMPARE(Ld1r(v29.V1D(), MemOperand(x13, 8, PostIndex)),
          "ld1r {v29.1d}, [x13], #8");

  COMPARE(Ld2r(v14.V8B(), v15.V8B(), MemOperand(x0)),
          "ld2r {v14.8b, v15.8b}, [x0]");
  COMPARE(Ld2r(v15.V16B(), v16.V16B(), MemOperand(x1)),
          "ld2r {v15.16b, v16.16b}, [x1]");
  COMPARE(Ld2r(v16.V4H(), v17.V4H(), MemOperand(x2)),
          "ld2r {v16.4h, v17.4h}, [x2]");
  COMPARE(Ld2r(v17.V8H(), v18.V8H(), MemOperand(x3)),
          "ld2r {v17.8h, v18.8h}, [x3]");
  COMPARE(Ld2r(v18.V2S(), v19.V2S(), MemOperand(x4)),
          "ld2r {v18.2s, v19.2s}, [x4]");
  COMPARE(Ld2r(v19.V4S(), v20.V4S(), MemOperand(x5)),
          "ld2r {v19.4s, v20.4s}, [x5]");
  COMPARE(Ld2r(v20.V2D(), v21.V2D(), MemOperand(sp)),
          "ld2r {v20.2d, v21.2d}, [sp]");
  COMPARE(Ld2r(v21.V8B(), v22.V8B(), MemOperand(x6, 2, PostIndex)),
          "ld2r {v21.8b, v22.8b}, [x6], #2");
  COMPARE(Ld2r(v22.V16B(), v23.V16B(), MemOperand(x7, x16, PostIndex)),
          "ld2r {v22.16b, v23.16b}, [x7], x16");
  COMPARE(Ld2r(v23.V4H(), v24.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld2r {v23.4h, v24.4h}, [x8], x17");
  COMPARE(Ld2r(v24.V8H(), v25.V8H(), MemOperand(x9, 4, PostIndex)),
          "ld2r {v24.8h, v25.8h}, [x9], #4");
  COMPARE(Ld2r(v25.V2S(), v26.V2S(), MemOperand(x10, 8, PostIndex)),
          "ld2r {v25.2s, v26.2s}, [x10], #8");
  COMPARE(Ld2r(v26.V4S(), v27.V4S(), MemOperand(x11, x18, PostIndex)),
          "ld2r {v26.4s, v27.4s}, [x11], x18");
  COMPARE(Ld2r(v27.V2D(), v28.V2D(), MemOperand(x12, 16, PostIndex)),
          "ld2r {v27.2d, v28.2d}, [x12], #16");

  COMPARE(Ld3r(v14.V8B(), v15.V8B(), v16.V8B(), MemOperand(x0)),
          "ld3r {v14.8b, v15.8b, v16.8b}, [x0]");
  COMPARE(Ld3r(v15.V16B(), v16.V16B(), v17.V16B(), MemOperand(x1)),
          "ld3r {v15.16b, v16.16b, v17.16b}, [x1]");
  COMPARE(Ld3r(v16.V4H(), v17.V4H(), v18.V4H(), MemOperand(x2)),
          "ld3r {v16.4h, v17.4h, v18.4h}, [x2]");
  COMPARE(Ld3r(v17.V8H(), v18.V8H(), v19.V8H(), MemOperand(x3)),
          "ld3r {v17.8h, v18.8h, v19.8h}, [x3]");
  COMPARE(Ld3r(v18.V2S(), v19.V2S(), v20.V2S(), MemOperand(x4)),
          "ld3r {v18.2s, v19.2s, v20.2s}, [x4]");
  COMPARE(Ld3r(v19.V4S(), v20.V4S(), v21.V4S(), MemOperand(x5)),
          "ld3r {v19.4s, v20.4s, v21.4s}, [x5]");
  COMPARE(Ld3r(v20.V2D(), v21.V2D(), v22.V2D(), MemOperand(sp)),
          "ld3r {v20.2d, v21.2d, v22.2d}, [sp]");
  COMPARE(Ld3r(v21.V8B(), v22.V8B(), v23.V8B(), MemOperand(x6, 3, PostIndex)),
          "ld3r {v21.8b, v22.8b, v23.8b}, [x6], #3");
  COMPARE(
      Ld3r(v22.V16B(), v23.V16B(), v24.V16B(), MemOperand(x7, x16, PostIndex)),
      "ld3r {v22.16b, v23.16b, v24.16b}, [x7], x16");
  COMPARE(Ld3r(v23.V4H(), v24.V4H(), v25.V4H(), MemOperand(x8, x17, PostIndex)),
          "ld3r {v23.4h, v24.4h, v25.4h}, [x8], x17");
  COMPARE(Ld3r(v24.V8H(), v25.V8H(), v26.V8H(), MemOperand(x9, 6, PostIndex)),
          "ld3r {v24.8h, v25.8h, v26.8h}, [x9], #6");
  COMPARE(Ld3r(v25.V2S(), v26.V2S(), v27.V2S(), MemOperand(x10, 12, PostIndex)),
          "ld3r {v25.2s, v26.2s, v27.2s}, [x10], #12");
  COMPARE(
      Ld3r(v26.V4S(), v27.V4S(), v28.V4S(), MemOperand(x11, x18, PostIndex)),
      "ld3r {v26.4s, v27.4s, v28.4s}, [x11], x18");
  COMPARE(Ld3r(v27.V2D(), v28.V2D(), v29.V2D(), MemOperand(x12, 24, PostIndex)),
          "ld3r {v27.2d, v28.2d, v29.2d}, [x12], #24");

  COMPARE(Ld4r(v14.V8B(), v15.V8B(), v16.V8B(), v17.V8B(), MemOperand(x0)),
          "ld4r {v14.8b, v15.8b, v16.8b, v17.8b}, [x0]");
  COMPARE(Ld4r(v15.V16B(), v16.V16B(), v17.V16B(), v18.V16B(), MemOperand(x1)),
          "ld4r {v15.16b, v16.16b, v17.16b, v18.16b}, [x1]");
  COMPARE(Ld4r(v16.V4H(), v17.V4H(), v18.V4H(), v19.V4H(), MemOperand(x2)),
          "ld4r {v16.4h, v17.4h, v18.4h, v19.4h}, [x2]");
  COMPARE(Ld4r(v17.V8H(), v18.V8H(), v19.V8H(), v20.V8H(), MemOperand(x3)),
          "ld4r {v17.8h, v18.8h, v19.8h, v20.8h}, [x3]");
  COMPARE(Ld4r(v18.V2S(), v19.V2S(), v20.V2S(), v21.V2S(), MemOperand(x4)),
          "ld4r {v18.2s, v19.2s, v20.2s, v21.2s}, [x4]");
  COMPARE(Ld4r(v19.V4S(), v20.V4S(), v21.V4S(), v22.V4S(), MemOperand(x5)),
          "ld4r {v19.4s, v20.4s, v21.4s, v22.4s}, [x5]");
  COMPARE(Ld4r(v20.V2D(), v21.V2D(), v22.V2D(), v23.V2D(), MemOperand(sp)),
          "ld4r {v20.2d, v21.2d, v22.2d, v23.2d}, [sp]");
  COMPARE(Ld4r(v21.V8B(), v22.V8B(), v23.V8B(), v24.V8B(),
               MemOperand(x6, 4, PostIndex)),
          "ld4r {v21.8b, v22.8b, v23.8b, v24.8b}, [x6], #4");
  COMPARE(Ld4r(v22.V16B(), v23.V16B(), v24.V16B(), v25.V16B(),
               MemOperand(x7, x16, PostIndex)),
          "ld4r {v22.16b, v23.16b, v24.16b, v25.16b}, [x7], x16");
  COMPARE(Ld4r(v23.V4H(), v24.V4H(), v25.V4H(), v26.V4H(),
               MemOperand(x8, x17, PostIndex)),
          "ld4r {v23.4h, v24.4h, v25.4h, v26.4h}, [x8], x17");
  COMPARE(Ld4r(v24.V8H(), v25.V8H(), v26.V8H(), v27.V8H(),
               MemOperand(x9, 8, PostIndex)),
          "ld4r {v24.8h, v25.8h, v26.8h, v27.8h}, [x9], #8");
  COMPARE(Ld4r(v25.V2S(), v26.V2S(), v27.V2S(), v28.V2S(),
               MemOperand(x10, 16, PostIndex)),
          "ld4r {v25.2s, v26.2s, v27.2s, v28.2s}, [x10], #16");
  COMPARE(Ld4r(v26.V4S(), v27.V4S(), v28.V4S(), v29.V4S(),
               MemOperand(x11, x18, PostIndex)),
          "ld4r {v26.4s, v27.4s, v28.4s, v29.4s}, [x11], x18");
  COMPARE(Ld4r(v27.V2D(), v28.V2D(), v29.V2D(), v30.V2D(),
               MemOperand(x12, 32, PostIndex)),
          "ld4r {v27.2d, v28.2d, v29.2d, v30.2d}, [x12], #32");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_load_all_lanes_unallocated) {
  SET_UP_MASM();

  const char* expected = "unallocated (NEONLoadStoreSingleStruct)";
  // LD1R (single structure) (no offset)
  COMPARE(dci(0x0d00c000), expected);  // L = 0
  COMPARE(dci(0x0d40d000), expected);  // S = 1
  // LD2R (single structure) (no offset)
  COMPARE(dci(0x0d20c000), expected);  // L = 0
  COMPARE(dci(0x0d60d000), expected);  // S = 1
  // LD3R (single structure) (no offset)
  COMPARE(dci(0x0d00e000), expected);  // L = 0
  COMPARE(dci(0x0d40f000), expected);  // S = 1
  // LD4R (single structure) (no offset)
  COMPARE(dci(0x0d20e000), expected);  // L = 0
  COMPARE(dci(0x0d60f000), expected);  // S = 1

  expected = "unallocated (NEONLoadStoreSingleStructPostIndex)";
  // LD1R (single structure) (post index)
  COMPARE(dci(0x0d80c000), expected);  // L = 0
  COMPARE(dci(0x0dc0d000), expected);  // S = 1
  // LD2R (single structure) (post index)
  COMPARE(dci(0x0da0c000), expected);  // L = 0
  COMPARE(dci(0x0de0d000), expected);  // S = 1
  // LD3R (single structure) (post index)
  COMPARE(dci(0x0d80e000), expected);  // L = 0
  COMPARE(dci(0x0dc0f000), expected);  // S = 1
  // LD4R (single structure) (post index)
  COMPARE(dci(0x0da0e000), expected);  // L = 0
  COMPARE(dci(0x0de0f000), expected);  // S = 1

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_3same) {
  SET_UP_MASM();

#define DISASM_INST(M, S) \
  COMPARE(Cmeq(v0.M, v1.M, v2.M), "cmeq v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmge(v0.M, v1.M, v2.M), "cmge v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmgt(v0.M, v1.M, v2.M), "cmgt v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmhi(v0.M, v1.M, v2.M), "cmhi v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmhs(v0.M, v1.M, v2.M), "cmhs v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Cmtst(v0.M, v1.M, v2.M), "cmtst v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Add(v0.M, v1.M, v2.M), "add v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sub(v3.M, v4.M, v5.M), "sub v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sabd(v3.M, v4.M, v5.M), "sabd v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uabd(v3.M, v4.M, v5.M), "uabd v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Saba(v3.M, v4.M, v5.M), "saba v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uaba(v3.M, v4.M, v5.M), "uaba v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smax(v3.M, v4.M, v5.M), "smax v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smin(v3.M, v4.M, v5.M), "smin v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umax(v3.M, v4.M, v5.M), "umax v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umin(v3.M, v4.M, v5.M), "umin v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Smaxp(v3.M, v4.M, v5.M), "smaxp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sminp(v3.M, v4.M, v5.M), "sminp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Umaxp(v3.M, v4.M, v5.M), "umaxp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uminp(v3.M, v4.M, v5.M), "uminp v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqadd(v6.M, v7.M, v8_.M), "uqadd v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqadd(v9.M, v10.M, v11.M), "sqadd v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqsub(v6.M, v7.M, v8_.M), "uqsub v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqsub(v9.M, v10.M, v11.M), "sqsub v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sshl(v12.M, v13.M, v14.M), "sshl v12." S ", v13." S ", v14." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Ushl(v15.M, v16.M, v17.M), "ushl v15." S ", v16." S ", v17." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqshl(v18.M, v19.M, v20.M), "sqshl v18." S ", v19." S ", v20." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqshl(v21.M, v22.M, v23.M), "uqshl v21." S ", v22." S ", v23." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Srshl(v24.M, v25.M, v26.M), "srshl v24." S ", v25." S ", v26." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Urshl(v27.M, v28.M, v29.M), "urshl v27." S ", v28." S ", v29." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqrshl(v30.M, v31.M, v0.M), "sqrshl v30." S ", v31." S ", v0." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uqrshl(v1.M, v2.M, v3.M), "uqrshl v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Shadd(v4.M, v5.M, v6.M), "shadd v4." S ", v5." S ", v6." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uhadd(v7.M, v8_.M, v9.M), "uhadd v7." S ", v8." S ", v9." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Srhadd(v10.M, v11.M, v12.M), "srhadd v10." S ", v11." S ", v12." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Urhadd(v13.M, v14.M, v15.M), "urhadd v13." S ", v14." S ", v15." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Shsub(v16.M, v17.M, v18.M), "shsub v16." S ", v17." S ", v18." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Uhsub(v19.M, v20.M, v21.M), "uhsub v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Addp(v19.M, v20.M, v21.M), "addp v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mla(v19.M, v20.M, v21.M), "mla v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mls(v19.M, v20.M, v21.M), "mls v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Mul(v19.M, v20.M, v21.M), "mul v19." S ", v20." S ", v21." S);
  NEON_FORMAT_LIST_BHS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqdmulh(v1.M, v2.M, v3.M), "sqdmulh v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_HS(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Sqrdmulh(v1.M, v2.M, v3.M), "sqrdmulh v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_HS(DISASM_INST)
#undef DISASM_INST

  COMPARE(And(v6.V8B(), v7.V8B(), v8_.V8B()), "and v6.8b, v7.8b, v8.8b");
  COMPARE(And(v6.V16B(), v7.V16B(), v8_.V16B()), "and v6.16b, v7.16b, v8.16b");

  COMPARE(Bic(v6.V8B(), v7.V8B(), v8_.V8B()), "bic v6.8b, v7.8b, v8.8b");
  COMPARE(Bic(v6.V16B(), v7.V16B(), v8_.V16B()), "bic v6.16b, v7.16b, v8.16b");

  COMPARE(Orr(v6.V8B(), v7.V8B(), v8_.V8B()), "orr v6.8b, v7.8b, v8.8b");
  COMPARE(Orr(v6.V16B(), v7.V16B(), v8_.V16B()), "orr v6.16b, v7.16b, v8.16b");

  COMPARE(Orr(v6.V8B(), v7.V8B(), v7.V8B()), "mov v6.8b, v7.8b");
  COMPARE(Orr(v6.V16B(), v7.V16B(), v7.V16B()), "mov v6.16b, v7.16b");

  COMPARE(Mov(v6.V8B(), v8_.V8B()), "mov v6.8b, v8.8b");
  COMPARE(Mov(v6.V16B(), v8_.V16B()), "mov v6.16b, v8.16b");

  COMPARE(Orn(v6.V8B(), v7.V8B(), v8_.V8B()), "orn v6.8b, v7.8b, v8.8b");
  COMPARE(Orn(v6.V16B(), v7.V16B(), v8_.V16B()), "orn v6.16b, v7.16b, v8.16b");

  COMPARE(Eor(v6.V8B(), v7.V8B(), v8_.V8B()), "eor v6.8b, v7.8b, v8.8b");
  COMPARE(Eor(v6.V16B(), v7.V16B(), v8_.V16B()), "eor v6.16b, v7.16b, v8.16b");

  COMPARE(Bif(v6.V8B(), v7.V8B(), v8_.V8B()), "bif v6.8b, v7.8b, v8.8b");
  COMPARE(Bif(v6.V16B(), v7.V16B(), v8_.V16B()), "bif v6.16b, v7.16b, v8.16b");

  COMPARE(Bit(v6.V8B(), v7.V8B(), v8_.V8B()), "bit v6.8b, v7.8b, v8.8b");
  COMPARE(Bit(v6.V16B(), v7.V16B(), v8_.V16B()), "bit v6.16b, v7.16b, v8.16b");

  COMPARE(Bsl(v6.V8B(), v7.V8B(), v8_.V8B()), "bsl v6.8b, v7.8b, v8.8b");
  COMPARE(Bsl(v6.V16B(), v7.V16B(), v8_.V16B()), "bsl v6.16b, v7.16b, v8.16b");

  COMPARE(Pmul(v6.V8B(), v7.V8B(), v8_.V8B()), "pmul v6.8b, v7.8b, v8.8b");
  COMPARE(Pmul(v6.V16B(), v7.V16B(), v8_.V16B()),
          "pmul v6.16b, v7.16b, v8.16b");

  CLEANUP();
}

TEST_F(DisasmArm64Test, neon_fp_3same) {
  SET_UP_MASM();

#define DISASM_INST(M, S) \
  COMPARE(Fadd(v0.M, v1.M, v2.M), "fadd v0." S ", v1." S ", v2." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fsub(v3.M, v4.M, v5.M), "fsub v3." S ", v4." S ", v5." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmul(v6.M, v7.M, v8_.M), "fmul v6." S ", v7." S ", v8." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fdiv(v9.M, v10.M, v11.M), "fdiv v9." S ", v10." S ", v11." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmin(v12.M, v13.M, v14.M), "fmin v12." S ", v13." S ", v14." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fminnm(v15.M, v16.M, v17.M), "fminnm v15." S ", v16." S ", v17." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmax(v18.M, v19.M, v20.M), "fmax v18." S ", v19." S ", v20." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmaxnm(v21.M, v22.M, v23.M), "fmaxnm v21." S ", v22." S ", v23." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Frecps(v24.M, v25.M, v26.M), "frecps v24." S ", v25." S ", v26." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Frsqrts(v27.M, v28.M, v29.M), "frsqrts v27." S ", v28." S \
                                        ", "                        \
                                        "v29." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmulx(v30.M, v31.M, v0.M), "fmulx v30." S ", v31." S ", v0." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmla(v1.M, v2.M, v3.M), "fmla v1." S ", v2." S ", v3." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmls(v4.M, v5.M, v6.M), "fmls v4." S ", v5." S ", v6." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fabd(v7.M, v8_.M, v9.M), "fabd v7." S ", v8." S ", v9." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Faddp(v10.M, v11.M, v12.M), "faddp v10." S ", v11." S ", v12." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fmaxp(v13.M, v14.M, v15.M), "fmaxp v13." S ", v14." S ", v15." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fminp(v16.M, v17.M, v18.M), "fminp v16." S ", v17." S ", v18." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Fmaxnmp(v19.M, v20.M, v21.M), "fmaxnmp v19." S ", v20." S \
                                        ", "                        \
                                        "v21." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S)                                           \
  COMPARE(Fminnmp(v22.M, v23.M, v24.M), "fminnmp v22." S ", v23." S \
                                        ", "                        \
                                        "v24." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmeq(v25.M, v26.M, v27.M), "fcmeq v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmge(v25.M, v26.M, v27.M), "fcmge v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Fcmgt(v25.M, v26.M, v27.M), "fcmgt v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Facge(v25.M, v26.M, v27.M), "facge v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

#define DISASM_INST(M, S) \
  COMPARE(Facgt(v25.M, v26.M, v27.M), "facgt v25." S ", v26." S ", v27." S);
  NEON_FORMAT_LIST_FP(DISASM_INST)
#undef DISASM_INST

  CLEANUP();
}

#define NEON_SCALAR_FORMAT_LIST(V) \
  V(B(), "b")                      \
  V(H(), "h")                      \
  V(S(), "s")                      \
  V(D(), "d")

TEST_F(DisasmArm64Test, neon_scalar_3same) {
  SET_UP_MASM();

  // Instructions that only support D-sized scalar operations.
  COMPARE(Add(v0.D(), v1.D(), v2.D()), "add d0, d1, d2");
  COMPARE(Sub(v3.D(), v4.D(), v5.D()), "sub d3, d4, d5");
  COMPARE(Cmeq(v0.D(), v1.D(), v2.D()), "cmeq d0, d1, d2");
  COMPARE(Cmge(v3.D(), v4.D(), v5.D()), "cmge d3, d4, d5");
  COMPARE(Cmgt(v6.D(), v7.D(), v8_.D()), "cmgt d6, d7, d8");
  COMPARE(Cmhi(v0.D(), v1.D(), v2.D()), "cmhi d0, d1, d2");
  COMPARE(Cmhs(v3.D(), v4.D(), v5.D()), "cmhs d3, d4, d5");
  COMPARE(Cmtst(v6.D(), v7.D(), v8_.D()), "cmtst d6, d7, d8");
  COMPARE(Ushl(v6.D(), v7.D(), v8_.D()), "ushl d6, d7, d8");
  COMPARE(Sshl(v6.D(), v7.D(), v8_.D()), "sshl d6, d7, d8");
  COMPARE(Urshl(v9.D(), v10.D(), v11.D()), "urshl d9, d10, d11");
  COMPARE(Srshl(v9.D(), v10.D(), v11.D()), "srshl d9, d10, d11");

  // Instructions that support S and D-sized scalar operations.
  COMPARE(Frecps(v12.S(), v13.S(), v14.S()), "frecps s12, s13, s14");
  COMPARE(Frecps(v15.D(), v16.D(), v17.D()), "frecps d15, d16, d17");
  COMPARE(Frsqrts(v18.S(), v19.S(), v20.S()), "frsqrts s18, s19, s20");
  COMPARE(Frsqrts(v21.D(), v22.D(), v23.D()), "frsqrts d21, d22, d23");
  COMPARE(Fmulx(v12.S(), v13.S(), v14.S()), "fmulx s12, s13, s14");
  COMPARE(Fmulx(v15.D(), v16.D(), v17.D()), "fmulx d15, d16, d17");
  COMPARE(Fcmeq(v12.S(), v13.S(), v14.S()), "fcmeq s12, s13, s14");
  COMPARE(Fcmeq(v15.D(), v16.D(), v17.D()), "fcmeq d15, d16, d17");
  COMPARE(Fcmge(v12.S(), v13.S(), v14.S()), "fcmge s12, s13, s14");
  COMPARE(Fcmge(v15.D(), v16.D(), v17.D()), "fcmge d15, d16, d17");
  COMPARE(Fcmgt(v12.S(), v13.S(), v14.S()), "fcmgt s12, s13, s14");
  COMPARE(Fcmgt(v15.D(), v16.D(), v17.D()), "fcmgt d15, d16, d17");
  COMPARE(Fcmge(v12.S(), v13.S(), v14.S()), "fcmge s12, s13, s14");
  COMPARE(Fcmge(v15.D(), v16.D(), v17.D()), "fcmge d15, d16, d17");
  COMPARE(Facgt(v12.S(), v1
```