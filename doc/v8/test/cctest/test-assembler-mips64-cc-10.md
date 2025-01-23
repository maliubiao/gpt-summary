Response:
Let's break down the thought process for analyzing this C++ code snippet from V8.

1. **Initial Scan and Identification of Key Elements:**

   - The code is primarily composed of `#define` macros. This immediately suggests it's about code generation or some form of parameterized functionality.
   - Many macros have a similar structure and naming pattern (e.g., `BINSR_DF`, `ADDV_DF`, `SUBV_DF`, etc.). The `_DF` suffix likely means "Define Function" or something similar.
   - The macros take arguments like `T`, `lanes`, and `mask`. This hints at operations being performed on different data types (`T`), across multiple parallel lanes of data (`lanes`), and possibly with bitwise masking (`mask`).
   - There's a recurring `for` loop structure iterating `i` from 0 to 2 and `j` from 0 to `lanes / 2`. This strongly suggests processing data in chunks or pairs within a larger structure.
   - Inside the inner loop, bitwise operations (`>>`, `&`, `|`, `<<`) and type casting are prevalent. This points to low-level manipulation of data at the bit level.
   -  Several macros include calls to standard library functions like `std::max`, `std::min`, `std::abs`, and arithmetic operations.

2. **Deciphering the `_DF` Suffix and Macro Purpose:**

   - The consistent `_DF` suffix across many macros makes it a crucial element. Considering the context of `test-assembler-mips64.cc`, it's highly probable that these macros are *defining* the *behavior* of MIPS64 assembly instructions. They are likely templates that will be instantiated with specific data types and lane counts to generate the logic for different SIMD (Single Instruction, Multiple Data) operations.

3. **Analyzing Individual Macro Structures:**

   - **Common Setup:** Most macros start by calculating `size_in_bits` based on `kMSARegSize` and `lanes`. `kMSARegSize` is likely the size of a MIPS MSA (SIMD) register in bits. This reinforces the idea of SIMD operations.
   - **Looping Structure:** The nested loops are processing data in chunks. The `lanes / 2` suggests processing pairs of elements within the SIMD register.
   - **Data Extraction:**  Lines like `T ws_op = static_cast<T>((ws[i] >> shift) & mask);` extract specific data elements from the `ws` array (likely a source operand register) based on the current lane (`j`) and bit mask.
   - **Operation Logic:**  Each macro implements a different core operation. `ADDV_DF` performs addition, `SUBV_DF` subtraction, `MAX_DF` finds the maximum, and so on.
   - **Result Assembly:** The results of the operation are then shifted and combined using bitwise OR to build the final result in the `res` variable, which is then written back to the `wd` array (likely the destination register).

4. **Connecting to MIPS64 Assembly:**

   - The filename `test-assembler-mips64.cc` is a strong indicator that this code is used for *testing* the MIPS64 assembler in V8.
   - The macros are likely defining the *semantic behavior* of different MIPS MSA instructions. When the assembler encounters a particular MSA instruction, these macros (instantiated with the correct types and lane counts) are used to simulate or verify its execution.

5. **Considering the `.tq` Extension:**

   - The prompt specifically mentions the `.tq` extension, which signifies Torque. Torque is V8's internal language for defining built-in functions and optimizing compiler intrinsics.
   - *However*, the provided code snippet is clearly C++ with `#define` macros, not Torque. Therefore, based on the provided snippet alone, the premise about the `.tq` extension is incorrect for *this specific code*.

6. **Relating to JavaScript (Hypothetically):**

   - While the provided C++ code is low-level, it ultimately supports JavaScript's ability to perform optimized operations, especially those involving arrays and numerical computations.
   -  JavaScript engines like V8 use SIMD instructions under the hood to accelerate array processing, graphics, and other computationally intensive tasks. The macros shown are likely part of the infrastructure that makes these optimizations possible on MIPS64.

7. **Inferring Functionality and Providing Examples:**

   - Based on the macro names and the operations they perform, it's possible to infer their functionality: bitwise shifts, arithmetic operations, comparisons, and more complex operations like saturated arithmetic.
   -  JavaScript examples are then constructed to demonstrate scenarios where these low-level SIMD operations might be employed by V8. Array manipulations and numerical calculations are prime candidates.

8. **Identifying Potential Programming Errors:**

   - The bitwise nature of the operations makes it prone to common errors: incorrect bit masks, off-by-one errors in shifts, and misunderstanding the behavior of signed vs. unsigned types. Examples are crafted to illustrate these pitfalls.

9. **Summarizing the Functionality:**

   - The final step is to synthesize the observations into a concise summary, highlighting the code's role in testing and defining the behavior of MIPS64 MSA instructions within V8.

**Self-Correction/Refinement During the Process:**

- Initially, one might focus solely on the bitwise operations. However, recognizing the `_DF` suffix and the context of "assembler tests" provides a much clearer understanding of the code's purpose.
-  The prompt about the `.tq` extension forces a check – is this actually Torque?  In this case, the code is clearly C++, so the premise is incorrect for this snippet. This highlights the importance of verifying assumptions.
- The connection to JavaScript isn't immediately obvious from the low-level C++ but becomes clear when considering how V8 uses SIMD for optimization.

By following this structured thought process, combining code analysis with contextual information, and being willing to refine initial assumptions, we can arrive at a comprehensive understanding of the provided V8 source code.
目录 `v8/test/cctest/test-assembler-mips64.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 MIPS64 架构的汇编器功能。

**功能列举:**

该文件定义了一系列的宏 (`#define`)，这些宏用于生成测试 MIPS64 架构 MSA (MIPS SIMD Architecture) 指令的 C++ 代码。这些宏模拟了 MSA 指令的行为，以便在测试环境中验证 V8 的汇编器是否正确地生成了这些指令。

具体来说，这些宏涵盖了以下类型的 MSA 操作：

* **位移操作 (Shift Operations):**  `SLL_DF` (逻辑左移), `SRL_DF` (逻辑右移), `BINSR_DF` (位插入)。
* **算术运算 (Arithmetic Operations):** `ADDV_DF` (加法), `SUBV_DF` (减法), `MULV_DF` (乘法), `MADDV_DF` (乘加), `MSUBV_DF` (乘减), `DIV_DF` (除法), `MOD_DF` (取模), `SRAR_DF` (算术右移)。
* **比较运算 (Comparison Operations):** `CEQ_DF` (相等比较), `CLT_DF` (小于比较), `CLE_DF` (小于等于比较).
* **绝对值运算 (Absolute Value Operations):** `MAXA_DF` (绝对值最大), `MINA_DF` (绝对值最小), `ADD_A_DF` (绝对值加法), `ASUB_S_DF` (绝对值减法).
* **饱和运算 (Saturating Arithmetic):** `ADDS_DF` (饱和加法), `SUBS_DF` (饱和减法), `ADDS_A_DF` (绝对值饱和加法), `SUBSUS_U_DF`, `SUBSUU_S_DF`.
* **平均值运算 (Average Operations):** `AVE_DF`, `AVER_DF`.
* **数据重排 (Data Rearrangement):** `PCKEV_DF` (打包偶数), `PCKOD_DF` (打包奇数), `ILVL_DF` (交错低位), `ILVR_DF` (交错高位), `ILVEV_DF` (交错偶数), `ILVOD_DF` (交错奇数), `VSHF_DF` (向量移位)。
* **半字操作 (Half-word Operations):** `HADD_DF` (半字加法), `HSUB_DF` (半字减法)。

**关于文件扩展名 `.tq`:**

如果 `v8/test/cctest/test-assembler-mips64.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是 V8 内部用于定义内置函数和优化编译器的领域特定语言。  然而，根据你提供的代码片段，这是一个 C++ 文件 (`.cc`)，不是 Torque 文件。

**与 JavaScript 的关系及示例:**

虽然这段代码是 C++，并且直接操作汇编指令，但它直接影响了 V8 执行 JavaScript 的性能。  MSA 指令是 MIPS64 架构提供的 SIMD (Single Instruction, Multiple Data) 指令集，允许并行处理多个数据。 V8 利用这些指令来加速 JavaScript 中涉及大量数值计算或数组操作的任务。

**JavaScript 示例:**

```javascript
function addArrays(arr1, arr2) {
  const result = [];
  for (let i = 0; i < arr1.length; i++) {
    result.push(arr1[i] + arr2[i]);
  }
  return result;
}

const a = [1, 2, 3, 4, 5, 6, 7, 8];
const b = [9, 10, 11, 12, 13, 14, 15, 16];
const sum = addArrays(a, b);
console.log(sum); // 输出 [10, 12, 14, 16, 18, 20, 22, 24]
```

在 MIPS64 架构上，当 V8 执行类似 `addArrays` 这样的函数时，它可能会利用 MSA 的加法指令（类似于 `ADDV_DF` 宏模拟的操作）来并行地执行多个加法运算，从而提高性能。例如，如果使用 128 位的 MSA 寄存器，并且数组元素是 32 位整数，那么一条 MSA 加法指令可以同时执行四个加法运算。

**代码逻辑推理 (假设输入与输出):**

以 `ADDV_DF` 宏为例，假设我们有以下输入：

* `T` 为 `int32_t` (32位有符号整数)
* `lanes` 为 4 (表示 4 个通道，每个通道处理一个 32 位整数)
* `mask` 为 `0xFFFFFFFF` (32 位全 1，用于屏蔽超出 32 位的溢出)
* `ws[0] = 0x0000000100000002` (低 32 位为 1，高 32 位为 2)
* `wt[0] = 0x0000000300000004` (低 32 位为 3，高 32 位为 4)
* `wd[0]` 的初始值不重要，因为会被覆盖。

根据 `ADDV_DF` 的逻辑：

1. `size_in_bits` 将是 `64 / 4 = 16`，但这在宏的实际应用中可能会有所不同，因为 `kMSARegSize` 通常是 128 位或更高。  假设 `kMSARegSize` 为 128，`size_in_bits` 将是 `128 / 4 = 32`。
2. 循环 `j` 从 0 到 `lanes / 2 - 1`，即 0 到 1。
3. **当 `j = 0` 时:**
   * `shift = 32 * 0 = 0`
   * `ws_op = (0x0000000100000002 >> 0) & 0xFFFFFFFF = 0x00000002`
   * `wt_op = (0x0000000300000004 >> 0) & 0xFFFFFFFF = 0x00000004`
   * `res |= (static_cast<uint64_t>(0x00000002 + 0x00000004) & 0xFFFFFFFF) << 0 = 0x00000006`
4. **当 `j = 1` 时:**
   * `shift = 32 * 1 = 32`
   * `ws_op = (0x0000000100000002 >> 32) & 0xFFFFFFFF = 0x00000001`
   * `wt_op = (0x0000000300000004 >> 32) & 0xFFFFFFFF = 0x00000003`
   * `res |= (static_cast<uint64_t>(0x00000001 + 0x00000003) & 0xFFFFFFFF) << 32 = 0x0000000400000006`
5. 最终，`wd[0]` 将被设置为 `0x0000000400000006`。

**用户常见的编程错误 (与宏模拟的操作相关):**

这些宏模拟的底层操作容易出现以下编程错误，尤其是在编写使用 SIMD 指令的代码时：

* **数据类型不匹配:**  例如，将浮点数传递给期望整数的 MSA 指令，或者使用大小不匹配的数据类型。
* **通道数错误:**  假设 MSA 指令处理 8 个 8 位值，但代码逻辑只处理了 4 个。
* **位移量错误:**  位移操作的位移量超出数据类型的范围，导致不可预测的结果。
* **溢出问题:**  在没有饱和的情况下进行加法或乘法运算，导致结果超出数据类型的表示范围。
* **掩码使用不当:**  未能正确使用掩码来选择或屏蔽特定的位或通道。
* **对齐问题:**  某些 SIMD 指令可能要求数据在内存中是对齐的，未对齐的访问会导致错误。

**示例 (JavaScript 中可能导致底层 MSA 指令错误的场景):**

```javascript
// 假设 V8 内部尝试使用 MSA 指令优化此操作

const shortArray = new Int16Array([1, 2, 3, 4]);
const byteArray = new Int8Array(shortArray.buffer); // 错误地将 shortArray 的 buffer 解释为 byte array

// 尝试对 byte array 进行操作，可能会导致 MSA 指令处理通道数错误或数据类型不匹配
for (let i = 0; i < byteArray.length; i++) {
  byteArray[i] += 1;
}
```

在这个例子中，将 `Int16Array` 的 `buffer` 错误地解释为 `Int8Array`，当 V8 尝试使用 MSA 指令并行处理这些字节时，可能会因为数据类型或通道数的预期不符而导致错误。

**第 11 部分，共 13 部分的功能归纳:**

作为第 11 部分，并且专注于 MIPS64 架构的汇编器测试，该部分的主要功能是：

* **定义并实现了一系列 C++ 宏，用于模拟 MIPS64 MSA 指令的行为。**
* **为各种 MSA 操作（算术、位移、比较、数据重排等）提供了测试基础。**
* **为后续的测试用例编写提供了构建块，这些测试用例将验证 V8 的 MIPS64 汇编器是否正确生成了相应的机器码。**

总而言之，这个代码片段是 V8 保证其在 MIPS64 架构上正确且高效运行的关键组成部分，它通过模拟硬件指令的行为来测试软件层面的汇编器实现。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-mips64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
\
      T r;                                                                   \
      if (bits == size_in_bits) {                                            \
        r = static_cast<T>(ws_op);                                           \
      } else {                                                               \
        uint64_t mask2 = ((1ull << bits) - 1) << (size_in_bits - bits);      \
        r = static_cast<T>((static_cast<T>(mask2) & ws_op) |                 \
                           (static_cast<T>(~mask2) & wd_op));                \
      }                                                                      \
      res |= static_cast<uint64_t>(r) << shift;                              \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define BINSR_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                     \
      T wd_op = static_cast<T>((wd[i] >> shift) & mask);                     \
      T shift_op = static_cast<T>(((wt[i] >> shift) & mask) % size_in_bits); \
      int64_t bits = shift_op + 1;                                           \
      T r;                                                                   \
      if (bits == size_in_bits) {                                            \
        r = static_cast<T>(ws_op);                                           \
      } else {                                                               \
        uint64_t mask2 = (1ull << bits) - 1;                                 \
        r = static_cast<T>((static_cast<T>(mask2) & ws_op) |                 \
                           (static_cast<T>(~mask2) & wd_op));                \
      }                                                                      \
      res |= static_cast<uint64_t>(r) << shift;                              \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define ADDV_DF(T, lanes, mask)                                      \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(ws_op + wt_op) & mask) << shift; \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define SUBV_DF(T, lanes, mask)                                      \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(ws_op - wt_op) & mask) << shift; \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define MAX_DF(T, lanes, mask)                                         \
  int size_in_bits = kMSARegSize / lanes;                              \
  for (int i = 0; i < 2; i++) {                                        \
    uint64_t res = 0;                                                  \
    for (int j = 0; j < lanes / 2; ++j) {                              \
      uint64_t shift = size_in_bits * j;                               \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);               \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);               \
      res |= (static_cast<uint64_t>(std::max<T>(ws_op, wt_op)) & mask) \
             << shift;                                                 \
    }                                                                  \
    wd[i] = res;                                                       \
  }

#define MIN_DF(T, lanes, mask)                                         \
  int size_in_bits = kMSARegSize / lanes;                              \
  for (int i = 0; i < 2; i++) {                                        \
    uint64_t res = 0;                                                  \
    for (int j = 0; j < lanes / 2; ++j) {                              \
      uint64_t shift = size_in_bits * j;                               \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);               \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);               \
      res |= (static_cast<uint64_t>(std::min<T>(ws_op, wt_op)) & mask) \
             << shift;                                                 \
    }                                                                  \
    wd[i] = res;                                                       \
  }

#define MAXA_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                     \
  for (int i = 0; i < 2; i++) {                                               \
    uint64_t res = 0;                                                         \
    for (int j = 0; j < lanes / 2; ++j) {                                     \
      uint64_t shift = size_in_bits * j;                                      \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                      \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                      \
      res |=                                                                  \
          (static_cast<uint64_t>(Nabs(ws_op) < Nabs(wt_op) ? ws_op : wt_op) & \
           mask)                                                              \
          << shift;                                                           \
    }                                                                         \
    wd[i] = res;                                                              \
  }

#define MINA_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                     \
  for (int i = 0; i < 2; i++) {                                               \
    uint64_t res = 0;                                                         \
    for (int j = 0; j < lanes / 2; ++j) {                                     \
      uint64_t shift = size_in_bits * j;                                      \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                      \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                      \
      res |=                                                                  \
          (static_cast<uint64_t>(Nabs(ws_op) > Nabs(wt_op) ? ws_op : wt_op) & \
           mask)                                                              \
          << shift;                                                           \
    }                                                                         \
    wd[i] = res;                                                              \
  }

#define CEQ_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                     \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                     \
      res |= (static_cast<uint64_t>(!Compare(ws_op, wt_op) ? -1ull : 0ull) & \
              mask)                                                          \
             << shift;                                                       \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define CLT_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                   \
  for (int i = 0; i < 2; i++) {                                             \
    uint64_t res = 0;                                                       \
    for (int j = 0; j < lanes / 2; ++j) {                                   \
      uint64_t shift = size_in_bits * j;                                    \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                    \
      res |= (static_cast<uint64_t>((Compare(ws_op, wt_op) == -1) ? -1ull   \
                                                                  : 0ull) & \
              mask)                                                         \
             << shift;                                                      \
    }                                                                       \
    wd[i] = res;                                                            \
  }

#define CLE_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                  \
  for (int i = 0; i < 2; i++) {                                            \
    uint64_t res = 0;                                                      \
    for (int j = 0; j < lanes / 2; ++j) {                                  \
      uint64_t shift = size_in_bits * j;                                   \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                   \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                   \
      res |= (static_cast<uint64_t>((Compare(ws_op, wt_op) != 1) ? -1ull   \
                                                                 : 0ull) & \
              mask)                                                        \
             << shift;                                                     \
    }                                                                      \
    wd[i] = res;                                                           \
  }

#define ADD_A_DF(T, lanes, mask)                                               \
  int size_in_bits = kMSARegSize / lanes;                                      \
  for (int i = 0; i < 2; i++) {                                                \
    uint64_t res = 0;                                                          \
    for (int j = 0; j < lanes / 2; ++j) {                                      \
      uint64_t shift = size_in_bits * j;                                       \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                       \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                       \
      res |= (static_cast<uint64_t>(Abs(ws_op) + Abs(wt_op)) & mask) << shift; \
    }                                                                          \
    wd[i] = res;                                                               \
  }

#define ADDS_A_DF(T, lanes, mask)                              \
  int size_in_bits = kMSARegSize / lanes;                      \
  for (int i = 0; i < 2; i++) {                                \
    uint64_t res = 0;                                          \
    for (int j = 0; j < lanes / 2; ++j) {                      \
      uint64_t shift = size_in_bits * j;                       \
      T ws_op = Nabs(static_cast<T>((ws[i] >> shift) & mask)); \
      T wt_op = Nabs(static_cast<T>((wt[i] >> shift) & mask)); \
      T r;                                                     \
      if (ws_op < -std::numeric_limits<T>::max() - wt_op) {    \
        r = std::numeric_limits<T>::max();                     \
      } else {                                                 \
        r = -(ws_op + wt_op);                                  \
      }                                                        \
      res |= (static_cast<uint64_t>(r) & mask) << shift;       \
    }                                                          \
    wd[i] = res;                                               \
  }

#define ADDS_DF(T, lanes, mask)                                        \
  int size_in_bits = kMSARegSize / lanes;                              \
  for (int i = 0; i < 2; i++) {                                        \
    uint64_t res = 0;                                                  \
    for (int j = 0; j < lanes / 2; ++j) {                              \
      uint64_t shift = size_in_bits * j;                               \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);               \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);               \
      res |= (static_cast<uint64_t>(SaturateAdd(ws_op, wt_op)) & mask) \
             << shift;                                                 \
    }                                                                  \
    wd[i] = res;                                                       \
  }

#define AVE_DF(T, lanes, mask)                                       \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(                                 \
                 ((wt_op & ws_op) + ((ws_op ^ wt_op) >> 1)) & mask)) \
             << shift;                                               \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define AVER_DF(T, lanes, mask)                                      \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(                                 \
                 ((wt_op | ws_op) - ((ws_op ^ wt_op) >> 1)) & mask)) \
             << shift;                                               \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define SUBS_DF(T, lanes, mask)                                        \
  int size_in_bits = kMSARegSize / lanes;                              \
  for (int i = 0; i < 2; i++) {                                        \
    uint64_t res = 0;                                                  \
    for (int j = 0; j < lanes / 2; ++j) {                              \
      uint64_t shift = size_in_bits * j;                               \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);               \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);               \
      res |= (static_cast<uint64_t>(SaturateSub(ws_op, wt_op)) & mask) \
             << shift;                                                 \
    }                                                                  \
    wd[i] = res;                                                       \
  }

#define SUBSUS_U_DF(T, lanes, mask)                           \
  using uT = typename std::make_unsigned<T>::type;            \
  int size_in_bits = kMSARegSize / lanes;                     \
  for (int i = 0; i < 2; i++) {                               \
    uint64_t res = 0;                                         \
    for (int j = 0; j < lanes / 2; ++j) {                     \
      uint64_t shift = size_in_bits * j;                      \
      uT ws_op = static_cast<uT>((ws[i] >> shift) & mask);    \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);      \
      T r;                                                    \
      if (wt_op > 0) {                                        \
        uT wtu = static_cast<uT>(wt_op);                      \
        if (wtu > ws_op) {                                    \
          r = 0;                                              \
        } else {                                              \
          r = static_cast<T>(ws_op - wtu);                    \
        }                                                     \
      } else {                                                \
        if (ws_op > std::numeric_limits<uT>::max() + wt_op) { \
          r = static_cast<T>(std::numeric_limits<uT>::max()); \
        } else {                                              \
          r = static_cast<T>(ws_op - wt_op);                  \
        }                                                     \
      }                                                       \
      res |= (static_cast<uint64_t>(r) & mask) << shift;      \
    }                                                         \
    wd[i] = res;                                              \
  }

#define SUBSUU_S_DF(T, lanes, mask)                        \
  using uT = typename std::make_unsigned<T>::type;         \
  int size_in_bits = kMSARegSize / lanes;                  \
  for (int i = 0; i < 2; i++) {                            \
    uint64_t res = 0;                                      \
    for (int j = 0; j < lanes / 2; ++j) {                  \
      uint64_t shift = size_in_bits * j;                   \
      uT ws_op = static_cast<uT>((ws[i] >> shift) & mask); \
      uT wt_op = static_cast<uT>((wt[i] >> shift) & mask); \
      uT wdu;                                              \
      T r;                                                 \
      if (ws_op > wt_op) {                                 \
        wdu = ws_op - wt_op;                               \
        if (wdu > std::numeric_limits<T>::max()) {         \
          r = std::numeric_limits<T>::max();               \
        } else {                                           \
          r = static_cast<T>(wdu);                         \
        }                                                  \
      } else {                                             \
        wdu = wt_op - ws_op;                               \
        CHECK(-std::numeric_limits<T>::max() ==            \
              std::numeric_limits<T>::min() + 1);          \
        if (wdu <= std::numeric_limits<T>::max()) {        \
          r = -static_cast<T>(wdu);                        \
        } else {                                           \
          r = std::numeric_limits<T>::min();               \
        }                                                  \
      }                                                    \
      res |= (static_cast<uint64_t>(r) & mask) << shift;   \
    }                                                      \
    wd[i] = res;                                           \
  }

#define ASUB_S_DF(T, lanes, mask)                                         \
  int size_in_bits = kMSARegSize / lanes;                                 \
  for (int i = 0; i < 2; i++) {                                           \
    uint64_t res = 0;                                                     \
    for (int j = 0; j < lanes / 2; ++j) {                                 \
      uint64_t shift = size_in_bits * j;                                  \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                  \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                  \
      res |= (static_cast<uint64_t>(Abs(ws_op - wt_op)) & mask) << shift; \
    }                                                                     \
    wd[i] = res;                                                          \
  }

#define ASUB_U_DF(T, lanes, mask)                                    \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(ws_op > wt_op ? ws_op - wt_op    \
                                                  : wt_op - ws_op) & \
              mask)                                                  \
             << shift;                                               \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define MULV_DF(T, lanes, mask)                                      \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      res |= (static_cast<uint64_t>(ws_op * wt_op) & mask) << shift; \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define MADDV_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                     \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                     \
      T wd_op = static_cast<T>((wd[i] >> shift) & mask);                     \
      res |= (static_cast<uint64_t>(wd_op + ws_op * wt_op) & mask) << shift; \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define MSUBV_DF(T, lanes, mask)                                             \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                     \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                     \
      T wd_op = static_cast<T>((wd[i] >> shift) & mask);                     \
      res |= (static_cast<uint64_t>(wd_op - ws_op * wt_op) & mask) << shift; \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define DIV_DF(T, lanes, mask)                                       \
  int size_in_bits = kMSARegSize / lanes;                            \
  for (int i = 0; i < 2; i++) {                                      \
    uint64_t res = 0;                                                \
    for (int j = 0; j < lanes / 2; ++j) {                            \
      uint64_t shift = size_in_bits * j;                             \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);             \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);             \
      if (wt_op == 0) {                                              \
        res = Unpredictable;                                         \
        break;                                                       \
      }                                                              \
      res |= (static_cast<uint64_t>(ws_op / wt_op) & mask) << shift; \
    }                                                                \
    wd[i] = res;                                                     \
  }

#define MOD_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                   \
  for (int i = 0; i < 2; i++) {                                             \
    uint64_t res = 0;                                                       \
    for (int j = 0; j < lanes / 2; ++j) {                                   \
      uint64_t shift = size_in_bits * j;                                    \
      T ws_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      T wt_op = static_cast<T>((wt[i] >> shift) & mask);                    \
      if (wt_op == 0) {                                                     \
        res = Unpredictable;                                                \
        break;                                                              \
      }                                                                     \
      res |= (static_cast<uint64_t>(wt_op != 0 ? ws_op % wt_op : 0) & mask) \
             << shift;                                                      \
    }                                                                       \
    wd[i] = res;                                                            \
  }

#define SRAR_DF(T, lanes, mask)                                              \
  int size_in_bits = kMSARegSize / lanes;                                    \
  for (int i = 0; i < 2; i++) {                                              \
    uint64_t res = 0;                                                        \
    for (int j = 0; j < lanes / 2; ++j) {                                    \
      uint64_t shift = size_in_bits * j;                                     \
      T src_op = static_cast<T>((ws[i] >> shift) & mask);                    \
      int shift_op = ((wt[i] >> shift) & mask) % size_in_bits;               \
      uint32_t bit = shift_op == 0 ? 0 : src_op >> (shift_op - 1) & 1;       \
      res |= (static_cast<uint64_t>(ArithmeticShiftRight(src_op, shift_op) + \
                                    bit) &                                   \
              mask)                                                          \
             << shift;                                                       \
    }                                                                        \
    wd[i] = res;                                                             \
  }

#define PCKEV_DF(T, lanes, mask)        \
  T* ws_p = reinterpret_cast<T*>(ws);   \
  T* wt_p = reinterpret_cast<T*>(wt);   \
  T* wd_p = reinterpret_cast<T*>(wd);   \
  for (int i = 0; i < lanes / 2; ++i) { \
    wd_p[i] = wt_p[2 * i];              \
    wd_p[i + lanes / 2] = ws_p[2 * i];  \
  }

#define PCKOD_DF(T, lanes, mask)           \
  T* ws_p = reinterpret_cast<T*>(ws);      \
  T* wt_p = reinterpret_cast<T*>(wt);      \
  T* wd_p = reinterpret_cast<T*>(wd);      \
  for (int i = 0; i < lanes / 2; ++i) {    \
    wd_p[i] = wt_p[2 * i + 1];             \
    wd_p[i + lanes / 2] = ws_p[2 * i + 1]; \
  }

#define ILVL_DF(T, lanes, mask)            \
  T* ws_p = reinterpret_cast<T*>(ws);      \
  T* wt_p = reinterpret_cast<T*>(wt);      \
  T* wd_p = reinterpret_cast<T*>(wd);      \
  for (int i = 0; i < lanes / 2; ++i) {    \
    wd_p[2 * i] = wt_p[i + lanes / 2];     \
    wd_p[2 * i + 1] = ws_p[i + lanes / 2]; \
  }

#define ILVR_DF(T, lanes, mask)         \
  T* ws_p = reinterpret_cast<T*>(ws);   \
  T* wt_p = reinterpret_cast<T*>(wt);   \
  T* wd_p = reinterpret_cast<T*>(wd);   \
  for (int i = 0; i < lanes / 2; ++i) { \
    wd_p[2 * i] = wt_p[i];              \
    wd_p[2 * i + 1] = ws_p[i];          \
  }

#define ILVEV_DF(T, lanes, mask)        \
  T* ws_p = reinterpret_cast<T*>(ws);   \
  T* wt_p = reinterpret_cast<T*>(wt);   \
  T* wd_p = reinterpret_cast<T*>(wd);   \
  for (int i = 0; i < lanes / 2; ++i) { \
    wd_p[2 * i] = wt_p[2 * i];          \
    wd_p[2 * i + 1] = ws_p[2 * i];      \
  }

#define ILVOD_DF(T, lanes, mask)        \
  T* ws_p = reinterpret_cast<T*>(ws);   \
  T* wt_p = reinterpret_cast<T*>(wt);   \
  T* wd_p = reinterpret_cast<T*>(wd);   \
  for (int i = 0; i < lanes / 2; ++i) { \
    wd_p[2 * i] = wt_p[2 * i + 1];      \
    wd_p[2 * i + 1] = ws_p[2 * i + 1];  \
  }

#define VSHF_DF(T, lanes, mask)                        \
  T* ws_p = reinterpret_cast<T*>(ws);                  \
  T* wt_p = reinterpret_cast<T*>(wt);                  \
  T* wd_p = reinterpret_cast<T*>(wd);                  \
  const int mask_not_valid = 0xC0;                     \
  const int mask_6bits = 0x3F;                         \
  for (int i = 0; i < lanes; ++i) {                    \
    if ((wd_p[i] & mask_not_valid)) {                  \
      wd_p[i] = 0;                                     \
    } else {                                           \
      int k = (wd_p[i] & mask_6bits) % (lanes * 2);    \
      wd_p[i] = k > lanes ? ws_p[k - lanes] : wt_p[k]; \
    }                                                  \
  }

#define HADD_DF(T, T_small, lanes)                                           \
  T_small* ws_p = reinterpret_cast<T_small*>(ws);                            \
  T_small* wt_p = reinterpret_cast<T_small*>(wt);                            \
  T* wd_p = reinterpret_cast<T*>(wd);                                        \
  for (int i = 0; i < lanes; ++i) {                                          \
    wd_p[i] = static_cast<T>(ws_p[2 * i + 1]) + static_cast<T>(wt_p[2 * i]); \
  }

#define HSUB_DF(T, T_small, lanes)                                           \
  T_small* ws_p = reinterpret_cast<T_small*>(ws);                            \
  T_small* wt_p = reinterpret_cast<T_small*>(wt);                            \
  T* wd_p = reinterpret_cast<T*>(wd);                                        \
  for (int i = 0; i < lanes; ++i) {                                          \
    wd_p[i] = static_cast<T>(ws_p[2 * i + 1]) - static_cast<T>(wt_p[2 * i]); \
  }

#define TEST_CASE(V)                                              \
  V(sll_b, SLL_DF, uint8_t, kMSALanesByte, UINT8_MAX)             \
  V(sll_h, SLL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)           \
  V(sll_w, SLL_DF, uint32_t, kMSALanesWord, UINT32_MAX)           \
  V(sll_d, SLL_DF, uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(srl_b, SRL_DF, uint8_t, kMSALanesByte, UINT8_MAX)             \
  V(srl_h, SRL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)           \
  V(srl_w, SRL_DF, uint32_t, kMSALanesWord, UINT32_MAX)           \
  V(srl_d, SRL_DF,
```