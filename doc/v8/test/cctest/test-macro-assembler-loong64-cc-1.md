Response:
The user wants a summary of the functionality of the provided C++ code snippet.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The code is a series of `TEST` macros within a C++ file. This strongly suggests it's a unit testing file. The filename `test-macro-assembler-loong64.cc` and the presence of `MacroAssembler` further indicate that it's testing the `MacroAssembler` for the LoongArch64 architecture.

2. **Analyze Individual Tests:** Examine the structure and operations within each `TEST` block. Notice the pattern:
    * Initialization (`CcTest::InitializeVM()`)
    * Setting up a memory buffer
    * Iterating through different input values and offsets using `FOR_UINT64_INPUTS` and `FOR_INT32_INPUTS2`
    * Defining lambda functions (`auto fn_...`) that use `MacroAssembler` instructions (like `__ Ld_b`, `__ St_b`, `__ Ld_h`, etc.)
    * Calling a `run_Unaligned` function to execute the generated assembly code and verify the results.

3. **Categorize the Tests:** Group the tests based on the instructions they are testing. Observe the naming conventions:
    * `Ld_b`: Tests byte load instructions (signed and unsigned).
    * `Ld_h`: Tests half-word load instructions (signed and unsigned).
    * `Ld_w`: Tests word load instructions (signed and unsigned).
    * `Ld_d`: Tests double-word load instructions.
    * `Fld_s`: Tests single-precision floating-point load/store.
    * `Fld_d`: Tests double-precision floating-point load/store.
    * `Sltu`: Tests the "set less than unsigned" instruction.
    * `macro_float_minmax_f32`, `macro_float_minmax_f64`: Test the `Float32Min/Max` and `Float64Min/Max` macros.
    * `SUB_W`, `SUB_D`: Test the `Sub_w` and `Sub_d` (subtract) instructions with immediate values.

4. **Identify Common Setup and Helper Functions:** Notice the `unsigned_test_values`, `unsigned_test_offset`, `unsigned_test_offset_increment`, and `sltu_test_values` functions. These provide sets of test data. Also, the `run_Unaligned` and `run_Sltu` functions are helper functions for executing the generated code.

5. **Infer the Overall Functionality:** Based on the individual tests, the file's primary function is to verify the correctness of various `MacroAssembler` instructions for memory access (loads and stores), arithmetic operations (like subtraction and comparisons), and floating-point operations on the LoongArch64 architecture. It focuses on testing with unaligned memory access and different data sizes (byte, half-word, word, double-word).

6. **Address Specific Instructions:** The prompt asks about the `.tq` extension and JavaScript relevance. The code is C++, not Torque, so that part is irrelevant. As it's low-level assembly testing, the direct connection to high-level JavaScript functionality might be indirect (it ensures the underlying architecture support for V8's JavaScript engine), but no direct JavaScript example applies.

7. **Code Logic and Assumptions:** The tests involve loading data from a memory buffer and storing it back, potentially with modifications. The assumption is that the `run_Unaligned` function sets up the memory buffer and calls the generated code correctly. Input and output examples would involve the specific values in the `kValues` arrays and the expected memory modifications after the assembly code runs.

8. **Common Programming Errors:**  The tests dealing with unaligned memory access implicitly touch upon a common programming error: attempting to access data at addresses that are not aligned to the data's size. This can lead to crashes or unexpected behavior on some architectures.

9. **Synthesize the Summary:** Combine the above observations into a concise description of the file's purpose.

10. **Review and Refine:** Ensure the summary is accurate, comprehensive, and addresses all aspects of the prompt. Specifically, since this is part 2 of a 4-part request, focus on summarizing the *current* code snippet's functionality.

This detailed thought process allows for a systematic understanding of the code and the generation of an informative summary.
好的，这是第2部分的代码分析，让我们继续归纳它的功能。

**功能归纳 (基于第2部分代码):**

这部分代码主要专注于测试 `v8` 虚拟机在 LoongArch64 架构上的 `MacroAssembler` 的内存加载和存储指令（load/store instructions），以及一些算术和比较指令，特别是针对不同数据大小和对齐方式的操作。

**具体功能点:**

1. **测试字节加载和存储指令 (`Ld_b`, `St_b`):**
   - 验证带符号和无符号字节加载指令 (`Ld_b`, `Ld_bu`) 的正确性。
   - 测试将加载的字节存储到内存中的功能 (`St_b`)。
   - 重点测试了非对齐内存访问的情况 (`run_Unaligned`)。
   - `Ld_b_bitextension` 测试了带符号和无符号字节加载在位扩展上的差异。

2. **测试半字加载和存储指令 (`Ld_h`, `St_h`):**
   - 类似于字节操作，测试了带符号和无符号半字加载指令 (`Ld_h`, `Ld_hu`) 的正确性。
   - 测试了半字存储指令 (`St_h`)。
   - 同样关注了非对齐内存访问。
   - `Ld_h_bitextension` 测试了带符号和无符号半字加载的位扩展行为。

3. **测试字加载和存储指令 (`Ld_w`, `St_w`):**
   - 测试了带符号和无符号字加载指令 (`Ld_w`, `Ld_wu`)。
   - 测试了字存储指令 (`St_w`)。
   - 包含非对齐访问的测试。
   - `Ld_w_extension` 测试了带符号和无符号字加载的扩展行为。

4. **测试双字加载和存储指令 (`Ld_d`, `St_d`):**
   - 测试了双字加载指令 (`Ld_d`)。
   - 测试了双字存储指令 (`St_d`)。
   - 包含非对齐访问的测试。

5. **测试浮点数加载和存储指令 (`Fld_s`, `Fst_s`, `Fld_d`, `Fst_d`):**
   - 测试了单精度浮点数加载 (`Fld_s`) 和存储 (`Fst_s`) 指令。
   - 测试了双精度浮点数加载 (`Fld_d`) 和存储 (`Fst_d`) 指令。
   - 包含非对齐访问的测试。

6. **测试无符号小于比较指令 (`Sltu`):**
   - 测试了 `Sltu` 指令，用于比较两个无符号数的大小，并将结果（0 或 1）存储到寄存器中。

7. **测试浮点数最小值和最大值宏 (`macro_float_minmax_f32`, `macro_float_minmax_f64`):**
   - 测试了 `Float32Min` 和 `Float32Max` 宏，用于计算单精度浮点数的最小值和最大值。
   - 测试了 `Float64Min` 和 `Float64Max` 宏，用于计算双精度浮点数的最小值和最大值。
   - 涵盖了各种输入情况，包括正常值、负零和 NaN (非数字)。

8. **测试减法指令 (`SUB_W`, `SUB_D`):**
   - 测试了带立即数的字减法指令 (`Sub_w`)，并检查了生成的指令数量，验证了 `MacroAssembler` 对不同立即数的处理。
   - 测试了带立即数的双字减法指令 (`Sub_d`)，同样检查了生成的指令数量。

**总结:**

这部分代码通过一系列的单元测试，详细验证了 LoongArch64 架构下 `MacroAssembler` 中各种内存操作指令、比较指令和算术指令的正确性。测试覆盖了不同数据类型（字节、半字、字、双字、浮点数）、带符号和无符号的情况，以及非对齐内存访问，确保了 `v8` 虚拟机在 LoongArch64 上的基础指令能够正确工作。  它还测试了浮点数的特殊情况处理 (NaN, 负零) 和带立即数的减法指令的指令生成效率。

**与 JavaScript 的关系:**

虽然这段代码是 C++ 写的，直接测试的是汇编指令，但它与 JavaScript 的功能息息相关。`MacroAssembler` 是 `v8` 虚拟机生成目标机器码的关键组件。  这些测试确保了当 `v8` 运行 JavaScript 代码并在 LoongArch64 架构上需要进行内存读写、比较或算术运算时，底层生成的机器码是正确的。

**假设输入与输出 (以 `TEST(Ld_b)` 为例):**

假设输入：

- `memory_buffer` 中某个地址（例如 `buffer_middle + out_offset`）的初始值为任意值。
- 寄存器 `a0` 指向 `buffer_middle`。
- `in_offset` 和 `out_offset` 的值为 `unsigned_test_offset` 和 `unsigned_test_offset_increment` 中取出的值，例如 `in_offset = -132 * KB`, `out_offset = -5`。
- `value` 为 `unsigned_test_values` 中取出的一个值，例如 `0x2180F18A06384414`，并且会转换为 `uint8_t`。

输出：

- 经过 `fn_1` 到 `fn_4` 其中之一的汇编代码执行后，`memory_buffer` 中地址 `buffer_middle + out_offset` 处的值应该等于从 `buffer_middle + in_offset` 读取的字节值。
- 寄存器 `a0` 的值会因为 `__ or_(a0, a2, zero_reg)` 的执行而改变，会与加载的字节值进行或运算。

**用户常见的编程错误:**

与这段代码相关的用户常见编程错误主要是**内存访问错误**：

1. **非对齐访问:**  在某些架构上，尝试以与其大小不符的地址访问数据会导致错误（例如，在奇数地址读取一个字）。虽然 LoongArch64 支持非对齐访问，但性能可能会受到影响。测试中的 `run_Unaligned` 函数正是为了验证在非对齐情况下的正确性。

   ```javascript
   // JavaScript 层面虽然不会直接操作内存地址，但底层的 v8 引擎需要处理这些
   // 例如，TypedArray 的操作如果跨越了某些内存页的边界，底层可能涉及非对齐访问
   const buffer = new ArrayBuffer(10);
   const view = new Uint32Array(buffer, 1); // 尝试在偏移量 1 处创建一个 Uint32Array，这可能导致非对齐访问
   ```

2. **缓冲区溢出/欠溢出:** 访问了超出分配缓冲区边界的内存。测试中设置了 `kBufferSize`，并使用偏移量来模拟在缓冲区内部的读写。如果偏移量过大或过小，可能会导致访问到无效内存。

   ```javascript
   const arr = new Array(10);
   arr[10] = 5; // 越界访问，在 C++ 中可能导致缓冲区溢出
   ```

3. **类型不匹配:**  尝试将一种类型的数据解释为另一种类型，可能导致数据损坏或意外行为。例如，用带符号加载指令读取无符号数据，或者反之。测试中的 `Ld_b` 和 `Ld_bu` 就体现了这种差异。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const view1 = new Int32Array(buffer);
   const view2 = new Uint32Array(buffer);

   view1[0] = -1; // 0xFFFFFFFF
   console.log(view2[0]); // 可能输出 4294967295，类型解释不同导致结果不同
   ```

希望这个更详细的归纳对您有所帮助！

Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ff
  static const uint64_t kValues[] = {
      0x2180F18A06384414, 0x000A714532102277, 0xBC1ACCCF180649F0,
      0x8000000080008000, 0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
  };
  // clang-format on
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset() {
  static const int32_t kValues[] = {// value, offset
                                    -132 * KB, -21 * KB, 0, 19 * KB, 135 * KB};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

static const std::vector<int32_t> unsigned_test_offset_increment() {
  static const int32_t kValues[] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5};
  return std::vector<int32_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

TEST(Ld_b) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_b(a2, MemOperand(a0, in_offset));
          __ St_b(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_b(a0, MemOperand(a0, in_offset));
          __ St_b(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_bu(a0, MemOperand(a0, in_offset));
          __ St_b(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_bu(a2, MemOperand(a0, in_offset));
          __ St_b(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn_4));
      }
    }
  }
}

TEST(Ld_b_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_b(t0, MemOperand(a0, in_offset));
          __ Ld_bu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_w(t0, t0, 7);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_w(t1, t1, 7);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_w(t0, t0, 7);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_b(t0, MemOperand(a0, in_offset));
          __ St_b(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_b(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint8_t>(buffer_middle, in_offset,
                                              out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_h) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_h(a2, MemOperand(a0, in_offset));
          __ St_h(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_h(a0, MemOperand(a0, in_offset));
          __ St_h(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_hu(a0, MemOperand(a0, in_offset));
          __ St_h(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_hu(a2, MemOperand(a0, in_offset));
          __ St_h(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_4));
      }
    }
  }
}

TEST(Ld_h_bitextension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint16_t value = static_cast<uint64_t>(*i & 0xFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_h(t0, MemOperand(a0, in_offset));
          __ Ld_hu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_w(t0, t0, 15);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_w(t1, t1, 15);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_w(t0, t0, 15);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_h(t0, MemOperand(a0, in_offset));
          __ St_h(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_h(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint16_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_w) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_w(a2, MemOperand(a0, in_offset));
          __ St_w(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_w(a0, MemOperand(a0, in_offset));
          __ St_w(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));

        auto fn_3 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_wu(a2, MemOperand(a0, in_offset));
          __ St_w(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_3));

        auto fn_4 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_wu(a0, MemOperand(a0, in_offset));
          __ St_w(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint32_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_4));
      }
    }
  }
}

TEST(Ld_w_extension) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint32_t value = static_cast<uint32_t>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          Label success, fail, end, different;
          __ Ld_w(t0, MemOperand(a0, in_offset));
          __ Ld_wu(t1, MemOperand(a0, in_offset));
          __ Branch(&different, ne, t0, Operand(t1));

          // If signed and unsigned values are same, check
          // the upper bits to see if they are zero
          __ srai_d(t0, t0, 31);
          __ Branch(&success, eq, t0, Operand(zero_reg));
          __ Branch(&fail);

          // If signed and unsigned values are different,
          // check that the upper bits are complementary
          __ bind(&different);
          __ srai_d(t1, t1, 31);
          __ Branch(&fail, ne, t1, Operand(1));
          __ srai_d(t0, t0, 31);
          __ addi_d(t0, t0, 1);
          __ Branch(&fail, ne, t0, Operand(zero_reg));
          // Fall through to success

          __ bind(&success);
          __ Ld_w(t0, MemOperand(a0, in_offset));
          __ St_w(t0, MemOperand(a0, out_offset));
          __ Branch(&end);
          __ bind(&fail);
          __ St_w(zero_reg, MemOperand(a0, out_offset));
          __ bind(&end);
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint32_t>(buffer_middle, in_offset,
                                               out_offset, value, fn));
      }
    }
  }
}

TEST(Ld_d) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        uint64_t value = *i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn_1 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ Ld_d(a2, MemOperand(a0, in_offset));
          __ St_d(a2, MemOperand(a0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true, run_Unaligned<uint64_t>(buffer_middle, in_offset,
                                               out_offset, value, fn_1));

        auto fn_2 = [](MacroAssembler* masm, int32_t in_offset,
                       int32_t out_offset) {
          __ mov(t0, a0);
          __ Ld_d(a0, MemOperand(a0, in_offset));
          __ St_d(a0, MemOperand(t0, out_offset));
          __ or_(a0, a2, zero_reg);
        };
        CHECK_EQ(true,
                 run_Unaligned<uint64_t>(buffer_middle, in_offset, out_offset,
                                         (uint32_t)value, fn_2));
      }
    }
  }
}

TEST(Fld_s) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        float value = static_cast<float>(*i & 0xFFFFFFFF);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Fld_s(f0, MemOperand(a0, in_offset));
          __ Fst_s(f0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<float>(buffer_middle, in_offset,
                                            out_offset, value, fn));
      }
    }
  }
}

TEST(Fld_d) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_UINT64_INPUTS(i, unsigned_test_values) {
    FOR_INT32_INPUTS2(j1, j2, unsigned_test_offset) {
      FOR_INT32_INPUTS2(k1, k2, unsigned_test_offset_increment) {
        double value = static_cast<double>(*i);
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        auto fn = [](MacroAssembler* masm, int32_t in_offset,
                     int32_t out_offset) {
          __ Fld_d(f0, MemOperand(a0, in_offset));
          __ Fst_d(f0, MemOperand(a0, out_offset));
        };
        CHECK_EQ(true, run_Unaligned<double>(buffer_middle, in_offset,
                                             out_offset, value, fn));
      }
    }
  }
}

static const std::vector<uint64_t> sltu_test_values() {
  // clang-format off
  static const uint64_t kValues[] = {
      0,
      1,
      0x7FE,
      0x7FF,
      0x800,
      0x801,
      0xFFE,
      0xFFF,
      0xFFFFFFFFFFFFF7FE,
      0xFFFFFFFFFFFFF7FF,
      0xFFFFFFFFFFFFF800,
      0xFFFFFFFFFFFFF801,
      0xFFFFFFFFFFFFFFFE,
      0xFFFFFFFFFFFFFFFF,
  };
  // clang-format on
  return std::vector<uint64_t>(&kValues[0], &kValues[arraysize(kValues)]);
}

template <typename Func>
bool run_Sltu(uint64_t rj, uint64_t rk, Func GenerateSltuInstructionFunc) {
  using F_CVT = int64_t(uint64_t x0, uint64_t x1, int x2, int x3, int x4);

  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assm;

  GenerateSltuInstructionFunc(masm, rk);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();

  auto f = GeneratedCode<F_CVT>::FromCode(isolate, *code);
  int64_t res = reinterpret_cast<int64_t>(f.Call(rj, rk, 0, 0, 0));
  return res == 1;
}

TEST(Sltu) {
  CcTest::InitializeVM();

  FOR_UINT64_INPUTS(i, sltu_test_values) {
    FOR_UINT64_INPUTS(j, sltu_test_values) {
      uint64_t rj = *i;
      uint64_t rk = *j;

      auto fn_1 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(a2, a0, Operand(imm));
      };
      CHECK_EQ(rj < rk, run_Sltu(rj, rk, fn_1));

      auto fn_2 = [](MacroAssembler* masm, uint64_t imm) {
        __ Sltu(a2, a0, a1);
      };
      CHECK_EQ(rj < rk, run_Sltu(rj, rk, fn_2));
    }
  }
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat32MinMax(MacroAssembler* masm) {
  T a = T::from_code(8);   // f8
  T b = T::from_code(9);   // f9
  T c = T::from_code(10);  // f10

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Fld_s(x, MemOperand(a0, offsetof(Inputs, src1_)));         \
  __ Fld_s(y, MemOperand(a0, offsetof(Inputs, src2_)));         \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Fst_s(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float32Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float32Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float32Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float32Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float32Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float32Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jirl(zero_reg, ra, 0);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float32MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float32MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float32MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float32MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float32MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float32MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f32) {
  // Test the Float32Min and Float32Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    float src1_;
    float src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat32MinMax<FPURegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                         \
             base::bit_cast<uint32_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                         \
             base::bit_cast<uint32_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  float nan_a = std::numeric_limits<float>::quiet_NaN();
  float nan_b = std::numeric_limits<float>::quiet_NaN();

  CHECK_MINMAX(1.0f, -1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(-1.0f, 1.0f, -1.0f, 1.0f);
  CHECK_MINMAX(0.0f, -1.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-1.0f, 0.0f, -1.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -1.0f, -1.0f, -0.0f);
  CHECK_MINMAX(-1.0f, -0.0f, -1.0f, -0.0f);
  CHECK_MINMAX(0.0f, 1.0f, 0.0f, 1.0f);
  CHECK_MINMAX(1.0f, 0.0f, 0.0f, 1.0f);

  CHECK_MINMAX(0.0f, 0.0f, 0.0f, 0.0f);
  CHECK_MINMAX(-0.0f, -0.0f, -0.0f, -0.0f);
  CHECK_MINMAX(-0.0f, 0.0f, -0.0f, 0.0f);
  CHECK_MINMAX(0.0f, -0.0f, -0.0f, 0.0f);

  CHECK_MINMAX(0.0f, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0f, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

template <typename T, typename Inputs, typename Results>
static GeneratedCode<F4> GenerateMacroFloat64MinMax(MacroAssembler* masm) {
  T a = T::from_code(8);   // f8
  T b = T::from_code(9);   // f9
  T c = T::from_code(10);  // f10

  Label ool_min_abc, ool_min_aab, ool_min_aba;
  Label ool_max_abc, ool_max_aab, ool_max_aba;

  Label done_min_abc, done_min_aab, done_min_aba;
  Label done_max_abc, done_max_aab, done_max_aba;

#define FLOAT_MIN_MAX(fminmax, res, x, y, done, ool, res_field) \
  __ Fld_d(x, MemOperand(a0, offsetof(Inputs, src1_)));         \
  __ Fld_d(y, MemOperand(a0, offsetof(Inputs, src2_)));         \
  __ fminmax(res, x, y, &ool);                                  \
  __ bind(&done);                                               \
  __ Fst_d(a, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float64Min, a, b, c, done_min_abc, ool_min_abc, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float64Min, a, a, b, done_min_aab, ool_min_aab, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float64Min, a, b, a, done_min_aba, ool_min_aba, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float64Max, a, b, c, done_max_abc, ool_max_abc, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float64Max, a, a, b, done_max_aab, ool_max_aab, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float64Max, a, b, a, done_max_aba, ool_max_aba, max_aba_);

#undef FLOAT_MIN_MAX

  __ jirl(zero_reg, ra, 0);

  // Generate out-of-line cases.
  __ bind(&ool_min_abc);
  __ Float64MinOutOfLine(a, b, c);
  __ Branch(&done_min_abc);

  __ bind(&ool_min_aab);
  __ Float64MinOutOfLine(a, a, b);
  __ Branch(&done_min_aab);

  __ bind(&ool_min_aba);
  __ Float64MinOutOfLine(a, b, a);
  __ Branch(&done_min_aba);

  __ bind(&ool_max_abc);
  __ Float64MaxOutOfLine(a, b, c);
  __ Branch(&done_max_abc);

  __ bind(&ool_max_aab);
  __ Float64MaxOutOfLine(a, a, b);
  __ Branch(&done_max_aab);

  __ bind(&ool_max_aba);
  __ Float64MaxOutOfLine(a, b, a);
  __ Branch(&done_max_aba);

  CodeDesc desc;
  masm->GetCode(masm->isolate(), &desc);
  Handle<Code> code =
      Factory::CodeBuilder(masm->isolate(), desc, CodeKind::FOR_TESTING)
          .Build();
#ifdef DEBUG
  Print(*code);
#endif
  return GeneratedCode<F4>::FromCode(masm->isolate(), *code);
}

TEST(macro_float_minmax_f64) {
  // Test the Float64Min and Float64Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  struct Inputs {
    double src1_;
    double src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro assembler.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  GeneratedCode<F4> f =
      GenerateMacroFloat64MinMax<DoubleRegister, Inputs, Results>(masm);

#define CHECK_MINMAX(src1, src2, min, max)                          \
  do {                                                              \
    Inputs inputs = {src1, src2};                                   \
    Results results;                                                \
    f.Call(&inputs, &results, 0, 0, 0);                             \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(min),                         \
             base::bit_cast<uint64_t>(results.min_aba_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_abc_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aab_));           \
    CHECK_EQ(base::bit_cast<uint64_t>(max),                         \
             base::bit_cast<uint64_t>(results.max_aba_));           \
    /* Use a base::bit_cast to correctly identify -0.0 and NaNs. */ \
  } while (0)

  double nan_a = std::numeric_limits<double>::quiet_NaN();
  double nan_b = std::numeric_limits<double>::quiet_NaN();

  CHECK_MINMAX(1.0, -1.0, -1.0, 1.0);
  CHECK_MINMAX(-1.0, 1.0, -1.0, 1.0);
  CHECK_MINMAX(0.0, -1.0, -1.0, 0.0);
  CHECK_MINMAX(-1.0, 0.0, -1.0, 0.0);
  CHECK_MINMAX(-0.0, -1.0, -1.0, -0.0);
  CHECK_MINMAX(-1.0, -0.0, -1.0, -0.0);
  CHECK_MINMAX(0.0, 1.0, 0.0, 1.0);
  CHECK_MINMAX(1.0, 0.0, 0.0, 1.0);

  CHECK_MINMAX(0.0, 0.0, 0.0, 0.0);
  CHECK_MINMAX(-0.0, -0.0, -0.0, -0.0);
  CHECK_MINMAX(-0.0, 0.0, -0.0, 0.0);
  CHECK_MINMAX(0.0, -0.0, -0.0, 0.0);

  CHECK_MINMAX(0.0, nan_a, nan_a, nan_a);
  CHECK_MINMAX(nan_a, 0.0, nan_a, nan_a);
  CHECK_MINMAX(nan_a, nan_b, nan_a, nan_a);
  CHECK_MINMAX(nan_b, nan_a, nan_b, nan_b);

#undef CHECK_MINMAX
}

uint64_t run_Sub_w(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label code_start;
  __ bind(&code_start);
  __ Sub_w(a2, zero_reg, Operand(imm));
  CHECK_EQ(masm->InstructionsGeneratedSince(&code_start), num_instr);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(SUB_W) {
  CcTest::InitializeVM();

  // Test Subu macro-instruction for min_int12 and max_int12 border cases.
  // For subtracting int16 immediate values we use addiu.

  struct TestCaseSub {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };

  // We call Sub_w(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSub tc[] = {
      //              imm, expected_res, num_instr
      {0xFFFFFFFFFFFFF800,        0x800,         2},  // min_int12
      // The test case above generates ori + add_w instruction sequence.
      // We can't have just addi_ because -min_int12 > max_int12 so use
      // register. We can load min_int12 to at register with addi_w and then
      // subtract at with sub_w, but now we use ori + add_w because -min_int12
      // can be loaded using ori.
      {0x800,        0xFFFFFFFFFFFFF800,         1},  // max_int12 + 1
      // Generates addi_w
      // max_int12 + 1 is not int12 but -(max_int12 + 1) is, just use addi_w.
      {0xFFFFFFFFFFFFF7FF,        0x801,         2},  // min_int12 - 1
      // Generates ori + add_w
      // To load this value to at we need two instructions and another one to
      // subtract, lu12i + ori + sub_w. But we can load -value to at using just
      // ori and then add at register with add_w.
      {0x801,        0xFFFFFFFFFFFFF7FF,         2},  // max_int12 + 2
      // Generates ori + sub_w
      // Not int12 but is uint12, load value to at with ori and subtract with
      // sub_w.
      {0x00010000,   0xFFFFFFFFFFFF0000,         2},
      // Generates lu12i_w + sub_w
      // Load value using lui to at and subtract with subu.
      {0x00010001,   0xFFFFFFFFFFFEFFFF,         3},
      // Generates lu12i + ori + sub_w
      // We have to generate three instructions in this case.
      {0x7FFFFFFF,   0xFFFFFFFF80000001,         3},  // max_int32
      // Generates lu12i_w + ori + sub_w
      {0xFFFFFFFF80000000, 0xFFFFFFFF80000000,   2},  // min_int32
      // The test case above generates lu12i + sub_w intruction sequence.
      // The result of 0 - min_int32 eqauls max_int32 + 1, which wraps around to
      // min_int32 again.
  };
  // clang-format on

  size_t nr_test_cases = sizeof(tc) / sizeof(TestCaseSub);
  for (size_t i = 0; i < nr_test_cases; ++i) {
    CHECK_EQ(tc[i].expected_res, run_Sub_w(tc[i].imm, tc[i].num_instr));
  }
}

uint64_t run_Sub_d(uint64_t imm, int32_t num_instr) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assembler(isolate, v8::internal::CodeObjectRequired::kYes);
  MacroAssembler* masm = &assembler;

  Label code_start;
  __ bind(&code_start);
  __ Sub_d(a2, zero_reg, Operand(imm));
  CHECK_EQ(masm->InstructionsGeneratedSince(&code_start), num_instr);
  __ or_(a0, a2, zero_reg);
  __ jirl(zero_reg, ra, 0);

  CodeDesc desc;
  masm->GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F2>::FromCode(isolate, *code);

  uint64_t res = reinterpret_cast<uint64_t>(f.Call(0, 0, 0, 0, 0));

  return res;
}

TEST(SUB_D) {
  CcTest::InitializeVM();

  // Test Sub_d macro-instruction for min_int12 and max_int12 border cases.
  // For subtracting int12 immediate values we use addi_d.

  struct TestCaseSub {
    uint64_t imm;
    uint64_t expected_res;
    int32_t num_instr;
  };
  // We call Sub(v0, zero_reg, imm) to test cases listed below.
  // 0 - imm = expected_res
  // clang-format off
  struct TestCaseSub tc[] = {
      //              imm,       expected_res,  num_instr
      {0xFFFFFFFFFFFFF800,              0x800,         2},  // min_int12
      // The test case above generates addi_d instruction.
      // This is int12 value and we can load it using just addi_d.
      {             0x800, 0xFFFFFFFFFFFFF800,         1},  // max_int12 + 1
      // Generates addi_d
      // max_int12 + 1 is not int12 but is uint12, just
"""


```