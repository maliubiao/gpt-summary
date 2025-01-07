Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's testing framework.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The code consists of several `TEST` functions. This immediately indicates that it's part of a testing suite. The filename `test-macro-assembler-riscv64.cc` strongly suggests these tests are specifically for the `MacroAssembler` class on the RISC-V 64-bit architecture. `MacroAssembler` is a low-level component responsible for generating machine code.

2. **Analyze individual tests:** Examine each `TEST` function to understand what it's testing. Look for the following patterns:
    * **Setup:**  Initialization like `CcTest::InitializeVM()`.
    * **Code generation:**  Lambda functions passed to `run_Unaligned` or `GenAndRunTest`. These lambdas use `MacroAssembler` methods (like `__ ld`, `__ sd`, `__ Uld`, `__ Usd`, `__ Sltu`, `__ Float32Min`, etc.).
    * **Execution:**  Calls to `run_Unaligned` or `GenAndRunTest`. These functions likely compile and execute the generated code.
    * **Verification:** `CHECK_EQ` assertions comparing the actual results with expected values.
    * **Looping:** `FOR_UINT64_INPUTS`, `FOR_INT32_TWO_INPUTS`, `FOR_FLOAT32_INPUTS`, etc., indicating the tests are run with various inputs.

3. **Categorize the tests:** Group the tests based on the `MacroAssembler` instructions they are testing. For instance:
    * Unaligned loads/stores (`UnalignedLoadStore`)
    * Floating-point operations (`ULoadFloat`, `ULoadDouble`, `macro_float_minmax_f32`, `macro_float_minmax_f64`, `FCompare32_Branch`, `FCompare64_Branch`)
    * Integer comparisons (`Sltu`, `CompareI`)
    * Bit manipulation (`Clz32`, `Ctz32`, `Clz64`, `Ctz64`, `ByteSwap`, `Dpopcnt`, `Popcnt`)
    * Data movement (`Move`)
    * Deoptimization (`DeoptExitSizeIsFixed`)
    * Arithmetic with immediates (`AddWithImm`)

4. **Address specific points in the request:**
    * **Functionality:** Summarize the purpose of each test category.
    * **`.tq` extension:** Explain that this file is `.cc` and not a Torque file.
    * **Relationship to JavaScript:**  Explain that `MacroAssembler` is used to generate the low-level code that executes JavaScript. Provide simple JavaScript examples and how they *might* be translated to RISC-V instructions (even though the provided C++ doesn't directly *execute* JavaScript). Emphasize the connection through the runtime.
    * **Code logic推理 (reasoning):** Select a simpler test (like `Sltu`) and demonstrate how the input values and the `MacroAssembler` instructions lead to the expected output.
    * **Common programming errors:**  Think about the types of errors that could occur when working with unaligned memory access or floating-point comparisons, and relate them to the tested instructions.
    * **归纳功能 (summarize functionality):** Provide a concise overview of the entire code's purpose as a test suite for the RISC-V 64-bit `MacroAssembler`.

5. **Refine and organize:** Ensure the explanation is clear, well-structured, and addresses all aspects of the user's request. Use appropriate terminology (like "macro assembler," "machine code," "test suite").

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the RISC-V instructions.
* **Correction:** Realize the user needs the broader context of *why* these instructions are being tested, i.e., their role in executing JavaScript.
* **Initial thought:**  Directly link specific JavaScript code to the tested instructions.
* **Correction:**  Acknowledge that the provided C++ is for *testing* the assembler, not directly executing JavaScript. The connection is through the runtime code generation. Use examples that *illustrate* the concepts being tested.
* **Initial thought:**  Only describe what each test *does*.
* **Correction:** Also explain *why* these tests are important (e.g., ensuring correctness of low-level operations, handling edge cases like unaligned memory, validating floating-point behavior).

By following these steps and incorporating self-correction, a comprehensive and accurate answer can be constructed.
这是对 `v8/test/cctest/test-macro-assembler-riscv64.cc` 文件第二部分的分析和功能归纳。

**功能列举:**

这部分代码继续对 RISC-V 64 位架构的 `MacroAssembler` 类进行单元测试。它涵盖了以下方面的功能测试：

1. **未对齐的浮点数加载和存储 (Unaligned Floating-Point Load and Store):**
   - `ULoadFloat` 和 `UStoreFloat`：测试单精度浮点数的未对齐加载和存储操作。
   - `ULoadDouble` 和 `UStoreDouble`：测试双精度浮点数的未对齐加载和存储操作。

2. **无符号小于比较 (Sltu - Set Less Than Unsigned):**
   - 测试 `Sltu` 指令，比较两个无符号 64 位整数，并将结果 (0 或 1) 存储到目标寄存器。测试了与立即数和寄存器进行比较的情况。

3. **浮点数的最小值和最大值宏 (Float Min/Max Macros):**
   - `macro_float_minmax_f32`: 测试 `Float32Min` 和 `Float32Max` 宏，用于计算单精度浮点数的最小值和最大值。测试了不同的寄存器别名情况，以覆盖宏汇编器中的所有代码路径。
   - `macro_float_minmax_f64`: 测试 `Float64Min` 和 `Float64Max` 宏，用于计算双精度浮点数的最小值和最大值。同样测试了不同的寄存器别名情况。

4. **浮点数比较指令 (Floating-Point Compare Instructions):**
   - `FCompare32_Branch`: 测试 `CompareF32` 指令的各种条件码 (EQ, LT, LE, NE, GT, GE) 以及 `CompareIsNanF32` 指令（检查操作数是否为 NaN）。
   - `FCompare64_Branch`: 测试 `CompareF64` 指令的各种条件码以及 `CompareIsNanF64` 指令。

5. **整数比较指令 (Integer Compare Instructions):**
   - `CompareI`: 测试 `CompareI` 指令的各种条件码 (eq, ne, greater, greater_equal, less, less_equal, Ugreater, Ugreater_equal, Uless, Uless_equal)。测试了与立即数和寄存器进行比较的情况。

6. **前导零计数和尾部零计数 (Count Leading Zeros and Count Trailing Zeros):**
   - `Clz32`: 测试 `Clz32` 指令，计算 32 位整数前导零的数量。
   - `Ctz32`: 测试 `Ctz32` 指令，计算 32 位整数尾部零的数量。
   - `Clz64`: 测试 `Clz64` 指令，计算 64 位整数前导零的数量。
   - `Ctz64`: 测试 `Ctz64` 指令，计算 64 位整数尾部零的数量。

7. **字节交换 (Byte Swap):**
   - `ByteSwap`: 测试 `ByteSwap` 指令，交换 32 位或 64 位整数的字节序，使用临时寄存器。
   - `ByteSwap_no_scratch`: 测试 `ByteSwap` 指令，交换字节序，不使用临时寄存器。

8. **人口计数 (Population Count):**
   - `Dpopcnt`: 测试 `Popcnt64` 指令，计算 64 位整数中置位 (1) 的位数。
   - `Popcnt`: 测试 `Popcnt32` 指令，计算 32 位整数中置位的位数。

9. **数据移动 (Move):**
   - `Move`: 测试从双精度浮点数中提取高位字和低位字的操作 (`ExtractHighWordFromF64`, `ExtractLowWordFromF64`)。

10. **反优化出口大小 (Deoptimization Exit Size):**
    - `DeoptExitSizeIsFixed`: 验证不同类型的反优化出口代码的大小是否符合预期。

11. **带立即数的加法 (Add with Immediate):**
    - `AddWithImm`: 测试 `Add64`, `Add32`, `Sub64`, `Sub32` 指令与立即数进行运算。

**关于文件类型和 JavaScript 关系:**

- `v8/test/cctest/test-macro-assembler-riscv64.cc` 文件以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。
- 尽管此文件本身不是 JavaScript 代码，但它与 JavaScript 的功能有密切关系。 `MacroAssembler` 是 V8 引擎中用于 **动态生成 RISC-V 64 位机器代码** 的核心组件。V8 在运行时编译 JavaScript 代码时，会使用 `MacroAssembler` 将高级的 JavaScript 操作转换为底层的机器指令。这些测试确保了 `MacroAssembler` 生成的 RISC-V 代码的正确性，从而保证了 JavaScript 代码在 RISC-V 64 位架构上的正确执行。

**JavaScript 示例说明:**

虽然这些测试直接操作的是底层的机器指令生成，但我们可以用 JavaScript 例子来理解它们测试的功能概念：

```javascript
// 未对齐的内存访问 (JavaScript 无法直接模拟未对齐访问，这通常是底层优化的细节)
// 但在 V8 内部，对于一些特定的优化场景，可能需要处理未对齐的数据。

// 浮点数比较
let a = 1.0;
let b = 2.0;
console.log(a < b); // 对应 FCompare 指令

// 计算最小值和最大值
let x = 5.5;
let y = 2.3;
console.log(Math.min(x, y)); // 对应 FloatMin 宏
console.log(Math.max(x, y)); // 对应 FloatMax 宏

// 位运算
let num = 8; // 二进制 1000
console.log(Math.clz32(num)); // 计算前导零，对应 Clz32 指令
console.log(num.toString(2).padStart(32, '0')); // 手动查看前导零

// 字节序 (JavaScript 通常不需要直接处理字节序，但这在底层数据处理中很重要)
// 例如，在处理 ArrayBuffer 时，不同的架构可能有不同的字节序。

// 人口计数
function countSetBits(n) { // JavaScript 没有直接的内置函数，需要手动实现
  let count = 0;
  while (n > 0) {
    n &= (n - 1);
    count++;
  }
  return count;
}
console.log(countSetBits(0b10110)); // 对应 Popcnt 指令
```

**代码逻辑推理 (以 `Sltu` 测试为例):**

**假设输入:**
- 寄存器 `a0` 的初始值为 `i` (来自 `FOR_UINT64_INPUTS(i)`)，例如 `i = 5`。
- 用于比较的立即数 `j` (来自 `FOR_UINT64_INPUTS(j)`)，例如 `j = 10`。

**执行的代码逻辑:**
```c++
auto fn_1 = [j](MacroAssembler& masm) { __ Sltu(a0, a0, Operand(j)); };
CHECK_EQ(i < j, GenAndRunTest<int32_t>(i, fn_1));
```

- `__ Sltu(a0, a0, Operand(j))` 指令会将 `a0` 的值与立即数 `j` 进行无符号比较。
- 如果 `a0` (即 `i`) 小于 `j`，则将 `a0` 设置为 1，否则设置为 0。
- `GenAndRunTest<int32_t>(i, fn_1)` 会执行这段生成的机器码，并将 `a0` 的最终值作为结果返回。
- `CHECK_EQ(i < j, ...)` 会检查表达式 `i < j` 的布尔值是否等于执行结果 (0 或 1)。

**输出:**
- 当 `i = 5`, `j = 10` 时，`i < j` 为 true，`Sltu` 指令会将 `a0` 设置为 1，`GenAndRunTest` 返回 1，`CHECK_EQ(true, 1)` 通过。
- 当 `i = 15`, `j = 10` 时，`i < j` 为 false，`Sltu` 指令会将 `a0` 设置为 0，`GenAndRunTest` 返回 0，`CHECK_EQ(false, 0)` 通过。

**用户常见的编程错误 (与测试相关的):**

1. **未对齐内存访问错误:** 在一些架构上，尝试访问未对齐的内存地址会导致程序崩溃或性能下降。测试 `ULoadFloat` 和 `ULoadDouble` 就是为了确保 V8 的代码能够正确处理这种情况，避免因未对齐访问而导致的错误。用户如果直接编写底层代码，需要特别注意内存对齐问题。

   ```c++
   // 错误的示例 (在某些情况下会导致问题)
   char buffer[5];
   float* ptr = reinterpret_cast<float*>(buffer + 1); // ptr 指向未对齐的地址
   //*ptr = 3.14; // 可能会崩溃或性能下降
   ```

2. **浮点数比较的陷阱:** 浮点数由于其表示方式，直接使用 `==` 进行相等比较可能不可靠。测试 `FCompare32_Branch` 和 `FCompare64_Branch` 验证了 V8 在处理浮点数比较时的正确性，包括对 NaN 的处理。用户在编写涉及浮点数比较的代码时，应该注意使用合适的容差或特殊函数来处理。

   ```javascript
   let a = 0.1 + 0.2;
   let b = 0.3;
   console.log(a === b); // false，因为浮点数精度问题
   ```

3. **位运算的误用:**  错误地使用位运算，例如在进行位移时没有考虑到有符号数和无符号数，可能会导致意想不到的结果。测试 `Clz`, `Ctz`, `ByteSwap`, `Popcnt` 等指令确保了 V8 正确地实现了这些位操作。

   ```javascript
   let num = -1;
   console.log(num >> 1);  // 有符号右移，结果仍然是 -1
   console.log(num >>> 1); // 无符号右移，结果会很大
   ```

**功能归纳:**

这部分 `v8/test/cctest/test-macro-assembler-riscv64.cc` 代码的主要功能是 **对 V8 引擎中 RISC-V 64 位架构的 `MacroAssembler` 类进行全面的单元测试**。它验证了 `MacroAssembler` 生成的 RISC-V 汇编代码对于各种操作 (包括未对齐的内存访问、浮点数运算、整数比较、位操作、数据移动和反优化) 的正确性。这些测试对于确保 V8 引擎在 RISC-V 64 位平台上能够正确、高效地执行 JavaScript 代码至关重要。通过覆盖各种输入和边界情况，这些测试有助于发现和修复 `MacroAssembler` 实现中的潜在错误，从而提高 V8 引擎的稳定性和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/test-macro-assembler-riscv64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-macro-assembler-riscv64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
sd(t0, MemOperand(a0, out_offset));
  };

  auto fn_2 = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ mv(t0, a0);
    __ Uld(a0, MemOperand(a0, in_offset));
    __ Usd(a0, MemOperand(t0, out_offset));
  };

  FOR_UINT64_INPUTS(i) {
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;

        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn_1));

        // test when loaded value overwrites base-register of load address
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn_2));
      }
    }
  }
}

auto fn = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
  __ ULoadFloat(fa0, MemOperand(a0, in_offset), t0);
  __ UStoreFloat(fa0, MemOperand(a0, out_offset), t0);
};

TEST(ULoadFloat) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  FOR_FLOAT32_INPUTS(i) {
    // skip nan because CHECK_EQ cannot handle NaN
    if (std::isnan(i)) continue;
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn));
      }
    }
  }
}

TEST(ULoadDouble) {
  CcTest::InitializeVM();

  static const int kBufferSize = 300 * KB;
  char memory_buffer[kBufferSize];
  char* buffer_middle = memory_buffer + (kBufferSize / 2);

  auto fn = [](MacroAssembler& masm, int32_t in_offset, int32_t out_offset) {
    __ ULoadDouble(fa0, MemOperand(a0, in_offset), t0);
    __ UStoreDouble(fa0, MemOperand(a0, out_offset), t0);
  };

  FOR_FLOAT64_INPUTS(i) {
    // skip nan because CHECK_EQ cannot handle NaN
    if (std::isnan(i)) continue;
    FOR_INT32_TWO_INPUTS(j1, j2, unsigned_test_offset) {
      FOR_INT32_TWO_INPUTS(k1, k2, unsigned_test_offset_increment) {
        auto value = i;
        int32_t in_offset = *j1 + *k1;
        int32_t out_offset = *j2 + *k2;
        CHECK_EQ(value, run_Unaligned(buffer_middle, in_offset, out_offset,
                                      value, fn));
      }
    }
  }
}

TEST(Sltu) {
  CcTest::InitializeVM();

  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      // compare against immediate value
      auto fn_1 = [j](MacroAssembler& masm) { __ Sltu(a0, a0, Operand(j)); };
      CHECK_EQ(i < j, GenAndRunTest<int32_t>(i, fn_1));
      // compare against registers
      auto fn_2 = [](MacroAssembler& masm) { __ Sltu(a0, a0, a1); };
      CHECK_EQ(i < j, GenAndRunTest<int32_t>(i, j, fn_2));
    }
  }
}

template <typename T, typename Inputs, typename Results>
static void GenerateMacroFloat32MinMax(MacroAssembler& masm) {
  T a = T::from_code(5);  // ft5
  T b = T::from_code(6);  // ft6
  T c = T::from_code(7);  // ft7

#define FLOAT_MIN_MAX(fminmax, res, x, y, res_field)        \
  __ LoadFloat(x, MemOperand(a0, offsetof(Inputs, src1_))); \
  __ LoadFloat(y, MemOperand(a0, offsetof(Inputs, src2_))); \
  __ fminmax(res, x, y);                                    \
  __ StoreFloat(res, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float32Min, a, b, c, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float32Min, a, a, b, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float32Min, a, b, a, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float32Max, a, b, c, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float32Max, a, a, b, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float32Max, a, b, a, max_aba_);

#undef FLOAT_MIN_MAX
}

TEST(macro_float_minmax_f32) {
  // Test the Float32Min and Float32Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct Inputs {
    float src1_;
    float src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro masm.
    float min_abc_;
    float min_aab_;
    float min_aba_;
    float max_abc_;
    float max_aab_;
    float max_aba_;
  };

  auto f = AssembleCode<F4>(
      isolate, GenerateMacroFloat32MinMax<FPURegister, Inputs, Results>);

#define CHECK_MINMAX(src1, src2, min, max)                                \
  do {                                                                    \
    Inputs inputs = {src1, src2};                                         \
    Results results;                                                      \
    f.Call(&inputs, &results, 0, 0, 0);                                   \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_abc_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_aab_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(min),                               \
             base::bit_cast<uint32_t>(results.min_aba_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(results.max_abc_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(results.max_aab_));                 \
    CHECK_EQ(base::bit_cast<uint32_t>(max),                               \
             base::bit_cast<uint32_t>(                                    \
                 results.max_aba_)); /* Use a base::bit_cast to correctly \
                              identify -0.0 and NaNs. */                  \
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
static void GenerateMacroFloat64MinMax(MacroAssembler& masm) {
  T a = T::from_code(5);  // ft5
  T b = T::from_code(6);  // ft6
  T c = T::from_code(7);  // ft7

#define FLOAT_MIN_MAX(fminmax, res, x, y, res_field)         \
  __ LoadDouble(x, MemOperand(a0, offsetof(Inputs, src1_))); \
  __ LoadDouble(y, MemOperand(a0, offsetof(Inputs, src2_))); \
  __ fminmax(res, x, y);                                     \
  __ StoreDouble(res, MemOperand(a1, offsetof(Results, res_field)))

  // a = min(b, c);
  FLOAT_MIN_MAX(Float64Min, a, b, c, min_abc_);
  // a = min(a, b);
  FLOAT_MIN_MAX(Float64Min, a, a, b, min_aab_);
  // a = min(b, a);
  FLOAT_MIN_MAX(Float64Min, a, b, a, min_aba_);

  // a = max(b, c);
  FLOAT_MIN_MAX(Float64Max, a, b, c, max_abc_);
  // a = max(a, b);
  FLOAT_MIN_MAX(Float64Max, a, a, b, max_aab_);
  // a = max(b, a);
  FLOAT_MIN_MAX(Float64Max, a, b, a, max_aba_);

#undef FLOAT_MIN_MAX
}

TEST(macro_float_minmax_f64) {
  // Test the Float64Min and Float64Max macros.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  struct Inputs {
    double src1_;
    double src2_;
  };

  struct Results {
    // Check all register aliasing possibilities in order to exercise all
    // code-paths in the macro masm.
    double min_abc_;
    double min_aab_;
    double min_aba_;
    double max_abc_;
    double max_aab_;
    double max_aba_;
  };

  auto f = AssembleCode<F4>(
      isolate, GenerateMacroFloat64MinMax<DoubleRegister, Inputs, Results>);

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

  double nan_a = qnan_d;
  double nan_b = qnan_d;

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

template <typename T>
static bool CompareF(T input1, T input2, FPUCondition cond) {
  switch (cond) {
    case EQ:
      return (input1 == input2);
    case LT:
      return (input1 < input2);
    case LE:
      return (input1 <= input2);
    case NE:
      return (input1 != input2);
    case GT:
      return (input1 > input2);
    case GE:
      return (input1 >= input2);
    default:
      UNREACHABLE();
  }
}

static bool CompareU(uint64_t input1, uint64_t input2, Condition cond) {
  switch (cond) {
    case eq:
      return (input1 == input2);
    case ne:
      return (input1 != input2);

    case Uless:
      return (input1 < input2);
    case Uless_equal:
      return (input1 <= input2);
    case Ugreater:
      return (input1 > input2);
    case Ugreater_equal:
      return (input1 >= input2);

    case less:
      return (static_cast<int64_t>(input1) < static_cast<int64_t>(input2));
    case less_equal:
      return (static_cast<int64_t>(input1) <= static_cast<int64_t>(input2));
    case greater:
      return (static_cast<int64_t>(input1) > static_cast<int64_t>(input2));
    case greater_equal:
      return (static_cast<int64_t>(input1) >= static_cast<int64_t>(input2));

    default:
      UNREACHABLE();
  }
}

static void FCompare32Helper(FPUCondition cond) {
  auto fn = [cond](MacroAssembler& masm) { __ CompareF32(a0, cond, fa0, fa1); };
  FOR_FLOAT32_INPUTS(i) {
    FOR_FLOAT32_INPUTS(j) {
      bool comp_res = CompareF(i, j, cond);
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(i, j, fn));
    }
  }
}

static void FCompare64Helper(FPUCondition cond) {
  auto fn = [cond](MacroAssembler& masm) { __ CompareF64(a0, cond, fa0, fa1); };
  FOR_FLOAT64_INPUTS(i) {
    FOR_FLOAT64_INPUTS(j) {
      bool comp_res = CompareF(i, j, cond);
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(i, j, fn));
    }
  }
}

TEST(FCompare32_Branch) {
  CcTest::InitializeVM();

  FCompare32Helper(EQ);
  FCompare32Helper(LT);
  FCompare32Helper(LE);
  FCompare32Helper(NE);
  FCompare32Helper(GT);
  FCompare32Helper(GE);

  // test CompareIsNanF32: return true if any operand isnan
  auto fn = [](MacroAssembler& masm) { __ CompareIsNanF32(a0, fa0, fa1); };
  CHECK_EQ(false, GenAndRunTest<int32_t>(1023.01f, -100.23f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(1023.01f, snan_f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_f, -100.23f, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_f, qnan_f, fn));
}

TEST(FCompare64_Branch) {
  CcTest::InitializeVM();
  FCompare64Helper(EQ);
  FCompare64Helper(LT);
  FCompare64Helper(LE);
  FCompare64Helper(NE);
  FCompare64Helper(GT);
  FCompare64Helper(GE);

  // test CompareIsNanF64: return true if any operand isnan
  auto fn = [](MacroAssembler& masm) { __ CompareIsNanF64(a0, fa0, fa1); };
  CHECK_EQ(false, GenAndRunTest<int32_t>(1023.01, -100.23, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(1023.01, snan_d, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_d, -100.23, fn));
  CHECK_EQ(true, GenAndRunTest<int32_t>(snan_d, qnan_d, fn));
}

static void CompareIHelper(Condition cond) {
  FOR_UINT64_INPUTS(i) {
    FOR_UINT64_INPUTS(j) {
      auto input1 = i;
      auto input2 = j;
      bool comp_res = CompareU(input1, input2, cond);
      // test compare against immediate value
      auto fn1 = [cond, input2](MacroAssembler& masm) {
        __ CompareI(a0, a0, Operand(input2), cond);
      };
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(input1, fn1));
      // test compare registers
      auto fn2 = [cond](MacroAssembler& masm) {
        __ CompareI(a0, a0, Operand(a1), cond);
      };
      CHECK_EQ(comp_res, GenAndRunTest<int32_t>(input1, input2, fn2));
    }
  }
}

TEST(CompareI) {
  CcTest::InitializeVM();
  CompareIHelper(eq);
  CompareIHelper(ne);

  CompareIHelper(greater);
  CompareIHelper(greater_equal);
  CompareIHelper(less);
  CompareIHelper(less_equal);

  CompareIHelper(Ugreater);
  CompareIHelper(Ugreater_equal);
  CompareIHelper(Uless);
  CompareIHelper(Uless_equal);
}

TEST(Clz32) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Clz32(a0, a0); };
  FOR_UINT32_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_clz(i), GenAndRunTest<int>(i, fn));
  }
}

TEST(Ctz32) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Ctz32(a0, a0); };
  FOR_UINT32_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_ctz(i), GenAndRunTest<int>(i, fn));
  }
}

TEST(Clz64) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Clz64(a0, a0); };
  FOR_UINT64_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_clzll(i), GenAndRunTest<int>(i, fn));
  }
}

TEST(Ctz64) {
  CcTest::InitializeVM();
  auto fn = [](MacroAssembler& masm) { __ Ctz64(a0, a0); };
  FOR_UINT64_INPUTS(i) {
    // __builtin_clzll(0) is undefined
    if (i == 0) continue;
    CHECK_EQ(__builtin_ctzll(i), GenAndRunTest<int>(i, fn));
  }
}

template <int NBYTES, bool USE_SCRATCH>
static void ByteSwapHelper() {
  DCHECK(NBYTES == 4 || NBYTES == 8);
  Func fn;
  if (USE_SCRATCH) {
    fn = [](MacroAssembler& masm) { __ ByteSwap(a0, a0, NBYTES, t0); };
  } else {
    fn = [](MacroAssembler& masm) { __ ByteSwap(a0, a0, NBYTES); };
  }

  if (NBYTES == 4) {
    CHECK_EQ((int32_t)0x89ab'cdef, GenAndRunTest<int32_t>(0xefcd'ab89, fn));
  } else {
    CHECK_EQ((int64_t)0x0123'4567'89ab'cdef,
             GenAndRunTest<int64_t>(0xefcd'ab89'6745'2301, fn));
  }
}

TEST(ByteSwap) {
  CcTest::InitializeVM();
  ByteSwapHelper<4, true>();
  ByteSwapHelper<8, true>();
}

TEST(ByteSwap_no_scratch) {
  CcTest::InitializeVM();
  ByteSwapHelper<4, false>();
  ByteSwapHelper<8, false>();
}

TEST(Dpopcnt) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  uint64_t in[9];
  uint64_t out[9];
  uint64_t result[9];
  uint64_t val = 0xffffffffffffffffl;
  uint64_t cnt = 64;

  for (int i = 0; i < 7; i++) {
    in[i] = val;
    out[i] = cnt;
    cnt >>= 1;
    val >>= cnt;
  }

  in[7] = 0xaf1000000000000bl;
  out[7] = 10;
  in[8] = 0xe030000f00003000l;
  out[8] = 11;

  auto fn = [&in](MacroAssembler& masm) {
    __ mv(a4, a0);
    for (int i = 0; i < 7; i++) {
      // Load constant.
      __ li(a3, Operand(in[i]));
      __ Popcnt64(a5, a3, t0);
      __ Sd(a5, MemOperand(a4));
      __ Add64(a4, a4, Operand(kSystemPointerSize));
    }
    __ li(a3, Operand(in[7]));
    __ Popcnt64(a5, a3, t0);
    __ Sd(a5, MemOperand(a4));
    __ Add64(a4, a4, Operand(kSystemPointerSize));

    __ li(a3, Operand(in[8]));
    __ Popcnt64(a5, a3, t0);
    __ Sd(a5, MemOperand(a4));
    __ Add64(a4, a4, Operand(kSystemPointerSize));
  };
  auto f = AssembleCode<FV>(isolate, fn);

  (void)f.Call(reinterpret_cast<int64_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 9; i++) {
    CHECK(out[i] == result[i]);
  }
}

TEST(Popcnt) {
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);

  uint64_t in[8];
  uint64_t out[8];
  uint64_t result[8];
  uint64_t val = 0xffffffff;
  uint64_t cnt = 32;

  for (int i = 0; i < 6; i++) {
    in[i] = val;
    out[i] = cnt;
    cnt >>= 1;
    val >>= cnt;
  }

  in[6] = 0xaf10000b;
  out[6] = 10;
  in[7] = 0xe03f3000;
  out[7] = 11;

  auto fn = [&in](MacroAssembler& masm) {
    __ mv(a4, a0);
    for (int i = 0; i < 6; i++) {
      // Load constant.
      __ li(a3, Operand(in[i]));
      __ Popcnt32(a5, a3, t0);
      __ Sd(a5, MemOperand(a4));
      __ Add64(a4, a4, Operand(kSystemPointerSize));
    }

    __ li(a3, Operand(in[6]));
    __ Popcnt64(a5, a3, t0);
    __ Sd(a5, MemOperand(a4));
    __ Add64(a4, a4, Operand(kSystemPointerSize));

    __ li(a3, Operand(in[7]));
    __ Popcnt64(a5, a3, t0);
    __ Sd(a5, MemOperand(a4));
    __ Add64(a4, a4, Operand(kSystemPointerSize));
  };
  auto f = AssembleCode<FV>(isolate, fn);

  (void)f.Call(reinterpret_cast<int64_t>(result), 0, 0, 0, 0);
  // Check results.
  for (int i = 0; i < 8; i++) {
    CHECK(out[i] == result[i]);
  }
}

TEST(Move) {
  CcTest::InitializeVM();
  union {
    double dval;
    int32_t ival[2];
  } t;

  {
    auto fn = [](MacroAssembler& masm) { __ ExtractHighWordFromF64(a0, fa0); };
    t.ival[0] = 256;
    t.ival[1] = -123;
    CHECK_EQ(static_cast<int64_t>(t.ival[1]),
             GenAndRunTest<int64_t>(t.dval, fn));
    t.ival[0] = 645;
    t.ival[1] = 127;
    CHECK_EQ(static_cast<int64_t>(t.ival[1]),
             GenAndRunTest<int64_t>(t.dval, fn));
  }

  {
    auto fn = [](MacroAssembler& masm) { __ ExtractLowWordFromF64(a0, fa0); };
    t.ival[0] = 256;
    t.ival[1] = -123;
    CHECK_EQ(static_cast<int64_t>(t.ival[0]),
             GenAndRunTest<int64_t>(t.dval, fn));
    t.ival[0] = -645;
    t.ival[1] = 127;
    CHECK_EQ(static_cast<int64_t>(t.ival[0]),
             GenAndRunTest<int64_t>(t.dval, fn));
  }
}

TEST(DeoptExitSizeIsFixed) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope handles(isolate);
  auto buffer = AllocateAssemblerBuffer();
  MacroAssembler masm(isolate, v8::internal::CodeObjectRequired::kYes,
                      buffer->CreateView());
  static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
  for (int i = 0; i < kDeoptimizeKindCount; i++) {
    DeoptimizeKind kind = static_cast<DeoptimizeKind>(i);
    Label before_exit;
    Builtin target = Deoptimizer::GetDeoptimizationEntry(kind);
    // Mirroring logic in code-generator.cc.
    if (kind == DeoptimizeKind::kLazy) {
      // CFI emits an extra instruction here.
      masm.BindExceptionHandler(&before_exit);
    } else {
      masm.bind(&before_exit);
    }
    masm.CallForDeoptimization(target, 42, &before_exit, kind, &before_exit,
                               &before_exit);
    CHECK_EQ(masm.SizeOfCodeGeneratedSince(&before_exit),
             kind == DeoptimizeKind::kLazy ? Deoptimizer::kLazyDeoptExitSize
                                           : Deoptimizer::kEagerDeoptExitSize);
  }
}

TEST(AddWithImm) {
  CcTest::InitializeVM();
#define Test(Op, Input, Expected)                                       \
  {                                                                     \
    auto fn = [](MacroAssembler& masm) { __ Op(a0, zero_reg, Input); }; \
    CHECK_EQ(static_cast<int64_t>(Expected), GenAndRunTest(fn));        \
  }

  Test(Add64, 4095, 4095);
  Test(Add32, 4095, 4095);
  Test(Sub64, 4095, -4095);
  Test(Sub32, 4095, -4095);
#undef Test
}

#undef __

}  // namespace internal
}  // namespace v8

"""


```