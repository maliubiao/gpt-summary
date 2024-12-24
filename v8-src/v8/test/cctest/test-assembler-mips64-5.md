Response: The user is asking for a summary of the functionality of the provided C++ code snippet. This is the sixth part of a seven-part file. The code seems to define a series of macros that implement vector operations for the MIPS64 architecture using MSA (MIPS SIMD Architecture).

Here's a breakdown of the thinking process:

1. **Identify the Core Task:** The code defines macros that operate on data within vectors. The presence of `kMSALanesByte`, `kMSALanesHalf`, etc., strongly suggests these are SIMD operations.

2. **Recognize the Pattern:** Many macros follow a similar structure:
   - Take a type `T`, number of lanes, and a mask as arguments.
   - Loop through the lanes (or half the lanes).
   - Extract operands from input vectors `ws` and `wt`.
   - Perform an operation.
   - Store the result in the output vector `wd`.

3. **Categorize the Operations:** Group the macros based on the operations they perform. Keywords like `SLL`, `SRL`, `ADD`, `SUB`, `MAX`, `MIN`, `MUL`, `DIV`, `PCK`, `ILV`, `VSHF`, `HADD`, `HSUB` are strong indicators of the operation type (shift, arithmetic, compare, pack, interleave, etc.).

4. **Infer Data Types and Sizes:** The macro names often include suffixes like `_b`, `_h`, `_w`, `_d`, suggesting byte, half-word, word, and double-word sizes. The `T` parameter represents the data type.

5. **Connect to Assembler Tests:** The `TEST_CASE` and `RUN_TEST` macros suggest this code is part of a testing framework for the MIPS64 assembler. It defines the expected behavior of different MSA instructions.

6. **Relate to JavaScript (If Possible):**  Since this is part of the V8 JavaScript engine's test suite, the operations likely correspond to low-level operations that the JavaScript engine might use for optimized array or numerical processing. JavaScript doesn't directly expose these low-level SIMD instructions in a 1:1 mapping, but the *concept* of vector operations is relevant. Think about how JavaScript engines might optimize array manipulations or numerical calculations behind the scenes.

7. **Illustrate with JavaScript (Conceptual):**  Provide examples of JavaScript code that *could* benefit from similar vector optimizations. Focus on array operations and numerical calculations where performing the same operation on multiple elements simultaneously would be advantageous. Avoid trying to create direct equivalents of the low-level macros in JavaScript, as this isn't the goal.

8. **Address the "Part 6 of 7" Context:**  This reinforces the idea that this is a specific section focusing on a particular set of MSA instructions.

9. **Refine the Summary:** Organize the findings into a clear and concise summary. Start with the high-level purpose and then delve into the details of the operations.

**Self-Correction/Refinement:**

* **Initial thought:**  Maybe try to map the C++ macros to specific JavaScript SIMD APIs.
* **Correction:**  This is probably too granular and might not accurately reflect the relationship. The C++ code tests the *implementation* of the assembler, while JavaScript's SIMD APIs are a higher-level abstraction. Focus on the *general concept* of vector operations.
* **Initial thought:** List every single macro and its exact function.
* **Correction:** This would be too verbose for a summary. Group similar macros and provide a general description of their functionality. The `TEST_CASE` macro already provides a good overview of the different instruction types.

By following these steps, we arrive at a comprehensive and accurate summary of the provided C++ code snippet.
这是一个C++源代码文件，属于V8 JavaScript引擎的测试部分，专门用于测试MIPS64架构上的汇编器功能。更具体地说，这部分代码着重于测试MIPS SIMD架构 (MSA) 的各种向量运算指令的正确性。

**功能归纳:**

这个代码片段的主要功能是定义了一系列的C++宏，这些宏模拟了MIPS64架构上MSA指令的行为。然后，它使用这些宏在C++代码中执行与MSA指令相同的操作，并与汇编器生成的代码的执行结果进行比较，以验证汇编器生成的目标代码是否正确地实现了这些MSA指令。

**与JavaScript的关系:**

V8引擎负责执行JavaScript代码。为了提高性能，V8会将部分JavaScript代码编译成机器码执行。对于支持SIMD的架构（如MIPS64），V8可能会利用这些SIMD指令来加速某些类型的JavaScript操作，特别是涉及到数组和数值计算的操作。

虽然JavaScript本身并没有直接对应这些底层MSA指令的语法，但V8引擎在底层实现中可能会使用它们来优化性能。

**JavaScript 示例 (概念性):**

假设JavaScript中有一段代码对两个数组进行逐元素相加：

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

在MIPS64架构上，V8的优化编译器可能会将这个循环转换成使用MSA的向量加法指令 (`ADDV_DF` 宏模拟的功能之一) 来并行处理多个元素的加法，从而提高执行效率。

**这个第6部分的功能:**

考虑到这是第6部分，并且之前的部分可能已经定义了基础的测试框架和一些简单的指令，这部分代码很可能专注于测试**更复杂或者特定类型的MSA向量运算指令**。 从代码中可以看到，它包含了大量的宏定义，涵盖了各种操作，例如：

* **移位操作:** `SLL_DF`, `SRL_DF`, `SRA_DF` (逻辑左移，逻辑右移，算术右移)
* **位操作:** `BCRL_DF`, `BSET_DF`, `BNEG_DF` (位清除，位设置，位取反)
* **位插入/提取操作:** `BINSL_DF`, `BINSR_DF`
* **算术运算:** `ADDV_DF`, `SUBV_DF`, `MULV_DF`, `DIV_DF`, `MOD_DF` (向量加法，减法，乘法，除法，取模)
* **比较运算:** `MAX_DF`, `MIN_DF`, `CEQ_DF`, `CLT_DF`, `CLE_DF` (向量最大值，最小值，相等比较，小于比较，小于等于比较)
* **绝对值运算:** `ADD_A_DF`, `ASUB_S_DF`, `ASUB_U_DF`
* **饱和运算:** `ADDS_DF`, `SUBS_DF`, `SUBSUS_U_DF`, `SUBSUU_S_DF`
* **平均值运算:** `AVE_DF`, `AVER_DF`
* **乘加/乘减运算:** `MADDV_DF`, `MSUBV_DF`
* **数据重排操作:** `PCKEV_DF`, `PCKOD_DF`, `ILVL_DF`, `ILVR_DF`, `ILVEV_DF`, `ILVOD_DF`, `VSHF_DF` (打包，交错)
* **半字操作:** `HADD_DF`, `HSUB_DF`

因此，第6部分很可能着重测试这些**向量化的算术、逻辑、比较和数据处理指令**在MIPS64架构上的正确实现。  这些指令能够一次性处理多个数据元素，是实现高性能计算的关键。

总而言之，这部分代码是V8引擎中用于确保其在MIPS64架构上能够正确生成和执行使用MSA扩展的机器码的重要组成部分。它通过模拟MSA指令的行为并在C++中进行验证，来保证JavaScript代码在MIPS64上的高效且正确的执行。

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-mips64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
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
  V(srl_d, SRL_DF, uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(bclr_b, BCRL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bclr_h, BCRL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bclr_w, BCRL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bclr_d, BCRL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bset_b, BSET_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bset_h, BSET_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bset_w, BSET_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bset_d, BSET_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(bneg_b, BNEG_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(bneg_h, BNEG_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(bneg_w, BNEG_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(bneg_d, BNEG_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(binsl_b, BINSL_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsl_h, BINSL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsl_w, BINSL_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsl_d, BINSL_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(binsr_b, BINSR_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(binsr_h, BINSR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(binsr_w, BINSR_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(binsr_d, BINSR_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(addv_b, ADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(addv_h, ADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(addv_w, ADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(addv_d, ADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(subv_b, SUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(subv_h, SUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(subv_w, SUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(subv_d, SUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_s_b, MAX_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(max_s_h, MAX_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(max_s_w, MAX_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(max_s_d, MAX_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(max_u_b, MAX_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_u_h, MAX_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_u_w, MAX_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_u_d, MAX_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_s_b, MIN_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(min_s_h, MIN_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(min_s_w, MIN_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(min_s_d, MIN_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(min_u_b, MIN_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_u_h, MIN_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_u_w, MIN_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_u_d, MIN_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(max_a_b, MAXA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(max_a_h, MAXA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(max_a_w, MAXA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(max_a_d, MAXA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(min_a_b, MINA_DF, int8_t, kMSALanesByte, UINT8_MAX)           \
  V(min_a_h, MINA_DF, int16_t, kMSALanesHalf, UINT16_MAX)         \
  V(min_a_w, MINA_DF, int32_t, kMSALanesWord, UINT32_MAX)         \
  V(min_a_d, MINA_DF, int64_t, kMSALanesDword, UINT64_MAX)        \
  V(ceq_b, CEQ_DF, uint8_t, kMSALanesByte, UINT8_MAX)             \
  V(ceq_h, CEQ_DF, uint16_t, kMSALanesHalf, UINT16_MAX)           \
  V(ceq_w, CEQ_DF, uint32_t, kMSALanesWord, UINT32_MAX)           \
  V(ceq_d, CEQ_DF, uint64_t, kMSALanesDword, UINT64_MAX)          \
  V(clt_s_b, CLT_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(clt_s_h, CLT_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(clt_s_w, CLT_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(clt_s_d, CLT_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(clt_u_b, CLT_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(clt_u_h, CLT_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(clt_u_w, CLT_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(clt_u_d, CLT_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(cle_s_b, CLE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(cle_s_h, CLE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(cle_s_w, CLE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(cle_s_d, CLE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(cle_u_b, CLE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(cle_u_h, CLE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(cle_u_w, CLE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(cle_u_d, CLE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(add_a_b, ADD_A_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(add_a_h, ADD_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(add_a_w, ADD_A_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(add_a_d, ADD_A_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_a_b, ADDS_A_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(adds_a_h, ADDS_A_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(adds_a_w, ADDS_A_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(adds_a_d, ADDS_A_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(adds_s_b, ADDS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(adds_s_h, ADDS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(adds_s_w, ADDS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(adds_s_d, ADDS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(adds_u_b, ADDS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(adds_u_h, ADDS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(adds_u_w, ADDS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(adds_u_d, ADDS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ave_s_b, AVE_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(ave_s_h, AVE_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(ave_s_w, AVE_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(ave_s_d, AVE_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(ave_u_b, AVE_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ave_u_h, AVE_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ave_u_w, AVE_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ave_u_d, AVE_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(aver_s_b, AVER_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(aver_s_h, AVER_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(aver_s_w, AVER_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(aver_s_d, AVER_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(aver_u_b, AVER_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(aver_u_h, AVER_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(aver_u_w, AVER_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(aver_u_d, AVER_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subs_s_b, SUBS_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(subs_s_h, SUBS_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(subs_s_w, SUBS_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(subs_s_d, SUBS_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(subs_u_b, SUBS_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(subs_u_h, SUBS_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(subs_u_w, SUBS_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(subs_u_d, SUBS_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(subsus_u_b, SUBSUS_U_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsus_u_h, SUBSUS_U_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsus_u_w, SUBSUS_U_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsus_u_d, SUBSUS_U_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(subsuu_s_b, SUBSUU_S_DF, int8_t, kMSALanesByte, UINT8_MAX)    \
  V(subsuu_s_h, SUBSUU_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)  \
  V(subsuu_s_w, SUBSUU_S_DF, int32_t, kMSALanesWord, UINT32_MAX)  \
  V(subsuu_s_d, SUBSUU_S_DF, int64_t, kMSALanesDword, UINT64_MAX) \
  V(asub_s_b, ASUB_S_DF, int8_t, kMSALanesByte, UINT8_MAX)        \
  V(asub_s_h, ASUB_S_DF, int16_t, kMSALanesHalf, UINT16_MAX)      \
  V(asub_s_w, ASUB_S_DF, int32_t, kMSALanesWord, UINT32_MAX)      \
  V(asub_s_d, ASUB_S_DF, int64_t, kMSALanesDword, UINT64_MAX)     \
  V(asub_u_b, ASUB_U_DF, uint8_t, kMSALanesByte, UINT8_MAX)       \
  V(asub_u_h, ASUB_U_DF, uint16_t, kMSALanesHalf, UINT16_MAX)     \
  V(asub_u_w, ASUB_U_DF, uint32_t, kMSALanesWord, UINT32_MAX)     \
  V(asub_u_d, ASUB_U_DF, uint64_t, kMSALanesDword, UINT64_MAX)    \
  V(mulv_b, MULV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mulv_h, MULV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mulv_w, MULV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mulv_d, MULV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(maddv_b, MADDV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(maddv_h, MADDV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(maddv_w, MADDV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(maddv_d, MADDV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(msubv_b, MSUBV_DF, int8_t, kMSALanesByte, UINT8_MAX)          \
  V(msubv_h, MSUBV_DF, int16_t, kMSALanesHalf, UINT16_MAX)        \
  V(msubv_w, MSUBV_DF, int32_t, kMSALanesWord, UINT32_MAX)        \
  V(msubv_d, MSUBV_DF, int64_t, kMSALanesDword, UINT64_MAX)       \
  V(div_s_b, DIV_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(div_s_h, DIV_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(div_s_w, DIV_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(div_s_d, DIV_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(div_u_b, DIV_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(div_u_h, DIV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(div_u_w, DIV_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(div_u_d, DIV_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(mod_s_b, MOD_DF, int8_t, kMSALanesByte, UINT8_MAX)            \
  V(mod_s_h, MOD_DF, int16_t, kMSALanesHalf, UINT16_MAX)          \
  V(mod_s_w, MOD_DF, int32_t, kMSALanesWord, UINT32_MAX)          \
  V(mod_s_d, MOD_DF, int64_t, kMSALanesDword, UINT64_MAX)         \
  V(mod_u_b, MOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(mod_u_h, MOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(mod_u_w, MOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(mod_u_d, MOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(srlr_b, SRAR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(srlr_h, SRAR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(srlr_w, SRAR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(srlr_d, SRAR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(pckev_b, PCKEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckev_h, PCKEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckev_w, PCKEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckev_d, PCKEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(pckod_b, PCKOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(pckod_h, PCKOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(pckod_w, PCKOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(pckod_d, PCKOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvl_b, ILVL_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvl_h, ILVL_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvl_w, ILVL_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvl_d, ILVL_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvr_b, ILVR_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(ilvr_h, ILVR_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(ilvr_w, ILVR_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(ilvr_d, ILVR_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(ilvev_b, ILVEV_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvev_h, ILVEV_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvev_w, ILVEV_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvev_d, ILVEV_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(ilvod_b, ILVOD_DF, uint8_t, kMSALanesByte, UINT8_MAX)         \
  V(ilvod_h, ILVOD_DF, uint16_t, kMSALanesHalf, UINT16_MAX)       \
  V(ilvod_w, ILVOD_DF, uint32_t, kMSALanesWord, UINT32_MAX)       \
  V(ilvod_d, ILVOD_DF, uint64_t, kMSALanesDword, UINT64_MAX)      \
  V(vshf_b, VSHF_DF, uint8_t, kMSALanesByte, UINT8_MAX)           \
  V(vshf_h, VSHF_DF, uint16_t, kMSALanesHalf, UINT16_MAX)         \
  V(vshf_w, VSHF_DF, uint32_t, kMSALanesWord, UINT32_MAX)         \
  V(vshf_d, VSHF_DF, uint64_t, kMSALanesDword, UINT64_MAX)        \
  V(hadd_s_h, HADD_DF, int16_t, int8_t, kMSALanesHalf)            \
  V(hadd_s_w, HADD_DF, int32_t, int16_t, kMSALanesWord)           \
  V(hadd_s_d, HADD_DF, int64_t, int32_t, kMSALanesDword)          \
  V(hadd_u_h, HADD_DF, uint16_t, uint8_t, kMSALanesHalf)          \
  V(hadd_u_w, HADD_DF, uint32_t, uint16_t, kMSALanesWord)         \
  V(hadd_u_d, HADD_DF, uint64_t, uint32_t, kMSALanesDword)        \
  V(hsub_s_h, HSUB_DF, int16_t, int8_t, kMSALanesHalf)            \
  V(hsub_s_w, HSUB_DF, int32_t, int16_t, kMSALanesWord)           \
  V(hsub_s_d, HSUB_DF, int64_t, int32_t, kMSALanesDword)          \
  V(hsub_u_h, HSUB_DF, uint16_t, uint8_t, kMSALanesHalf)          \
  V(hsub_u_w, HSUB_DF, uint32_t, uint16_t, kMSALanesWord)         \
  V(hsub_u_d, HSUB_DF, uint64_t, uint32_t, kMSALanesDword)

#define RUN_TEST(instr, verify, type, lanes, mask)                       \
  run_msa_3r(&tc[i], [](MacroAssembler& assm) { __ instr(w2, w1, w0); }, \
             [](uint64_t* ws, uint64_t* wt, uint64_t* wd) {              \
               verify(type, lanes, mask);                                \
             });

  for (size_t i = 0; i < arraysize(tc); ++i) {
    TEST_CASE(RUN_TEST)
  }

#define RUN_TEST2(instr, verify, type, lanes, mask)                      \
  for (unsigned i = 0; i < arraysize(tc); i++) {                         \
    for (unsigned j = 0; j < 3; j++) {                                   \
      for (unsigned k = 0; k < lanes; k++) {                             \
        type* element = reinterpret_cast<type*>(&tc[i]);                 \
        element[k + j * lanes] &= std::numeric_limits<type>::max();      \
      }                                                                  \
    }                                                                    \
  }                                                                      \
  run_msa_3r(&tc[i], [](MacroAssembler& assm) { __ instr(w2, w1, w0); }, \
             [](uint64_t* ws, uint64_t* wt, uint64_t* wd) {              \
               verify(type, lanes, mask);                                \
             });

#define TEST_CASE2(V)                                    \
  V(sra_b, SRA_DF, int8_t, kMSALanesByte, UINT8_MAX)     \
  V(sra_h, SRA_DF, int16_t, kMSALanesHalf, UINT16_MAX)   \
  V(sra_w, SRA_DF, int32_t, kMSALanesWord, UINT32_MAX)   \
  V(sra_d, SRA_DF, int64_t, kMSALanesDword, UINT64_MAX)  \
  V(srar_b, SRAR_DF, int8_t, kMSALanesByte, UINT8_MAX)   \
  V(srar_h, SRAR_DF, int16_t, kMSALanesHalf, UINT16_MAX) \
  V(srar_w, SRAR_DF, int32_t, kMSALanesWord, UINT32_MAX) \
  V(srar_d, SRAR_DF, int64_t, kMSALanesDword, UINT64_MAX)

  for (size_t i = 0; i < arraysize(tc); ++i) {
    TEST_CASE2(RUN_TEST2)
  }

#undef TEST_CASE
#undef TEST_CASE2
#undef RUN_TEST
#undef RUN_TEST2
#undef SLL_DF
#undef SRL_DF
#undef SRA_DF
#undef BCRL_DF
#undef BSET_DF
#undef BNEG_DF
#undef BINSL_DF
#undef BINSR_DF
#undef ADDV_DF
#undef SUBV_DF
#undef MAX_DF
#undef MIN_DF
#undef MAXA_DF
#undef MINA_DF
#undef CEQ_DF
#undef CLT_DF
#undef CLE_DF
#undef ADD_A_DF
#undef ADDS_A_DF
#undef ADDS_DF
#undef AVE_DF
#undef AVER_DF
#undef SUBS_DF
#undef SUBSUS_U_DF
#undef SUBSUU_S_DF
#undef ASUB_S_DF
#undef ASUB_U_DF
#undef MULV_DF
#undef MADDV_DF
#undef MSUBV_DF
#undef DIV_DF
#undef MOD_DF
#undef SRAR_DF
#undef PCKEV_DF
#undef PCKOD_DF
#undef ILVL_DF
#undef ILVR_DF
#undef ILVEV_DF
#undef ILVOD_DF
#undef VSHF_DF
#undef HADD_DF
#undef HSUB_DF
}

struct TestCaseMsa3RF {
  uint64_t ws_lo;
  uint64_t ws_hi;
  uint64_t wt_lo;
  uint64_t wt_hi;
  uint64_t wd_lo;
  uint64_t wd_hi;
};

struct ExpectedResult_MSA3RF {
  uint64_t exp_res_lo;
  uint64_t exp_res_hi;
};

template <typename Func>
void run_msa_3rf(const struct TestCaseMsa3RF* input,
                 const struct ExpectedResult_MSA3RF* output,
                 Func Generate2RInstructionFunc) {
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  MacroAssembler assm(isolate, v8::internal::CodeObjectRequired::kYes);
  CpuFeatureScope fscope(&assm, MIPS_SIMD);
  msa_reg_t res;

  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->ws_lo), w0, t0, t1);
  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->wt_lo), w1, t0, t1);
  load_elements_of_vector(
      &assm, reinterpret_cast<const uint64_t*>(&input->wd_lo), w2, t0, t1);
  Generate2RInstructionFunc(assm);
  store_elements_of_vector(&assm, w2, a0);

  __ jr(ra);
  __ nop();

  CodeDesc desc;
  assm.GetCode(isolate, &desc);
  Handle<Code> code =
      Factory::CodeBuilder(isolate, desc, CodeKind::FOR_TESTING).Build();
#ifdef OBJECT_PRINT
  Print(*code);
#endif
  auto f = GeneratedCode<F3>::FromCode(isolate, *code);

  f.Call(&res, 0, 0, 0, 0);

  CHECK_EQ(output->exp_res_lo, res.d[0]);
  CHECK_EQ(output->exp_res_hi, res.d[1]);
}

struct TestCaseMsa3RF_F {
  float ws_1, ws_2, ws_3, ws_4;
  float wt_1, wt_2, wt_3, wt_4;
  float wd_1, wd_2, wd_3, wd_4;
};
struct ExpRes_32I {
  int32_t exp_res_1;
  int32_t exp_res_2;
  int32_t exp_res_3;
  int32_t exp_res_4;
};

struct TestCaseMsa3RF_D {
  double ws_lo, ws_hi;
  double wt_lo, wt_hi;
  double wd_lo, wd_hi;
};
struct ExpRes_64I {
  int64_t exp_res_lo;
  int64_t exp_res_hi;
};

TEST(MSA_floating_point_quiet_compare) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float qnan_f = std::numeric_limits<float>::quiet_NaN();
  const double qnan_d = std::numeric_limits<double>::quiet_NaN();
  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();
  const int32_t ones = -1;

  const struct TestCaseMsa3RF_F tc_w[]{
      {qnan_f, -qnan_f, inf_f, 2.14e9f,  // ws
       qnan_f, 0.f, qnan_f, -2.14e9f,    // wt
       0, 0, 0, 0},                      // wd
      {inf_f, -inf_f, -3.4e38f, 1.5e-45f, -inf_f, -inf_f, -inf_f, inf_f, 0, 0,
       0, 0},
      {0.f, 19.871e24f, -1.5e-45f, -1.5e-45f, -19.871e24f, 19.871e24f, 1.5e-45f,
       -1.5e-45f, 0, 0, 0, 0}};

  const struct TestCaseMsa3RF_D tc_d[]{
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {qnan_d, -qnan_d, qnan_f, 0., 0, 0},
      {inf_d, 9.22e18, qnan_d, -9.22e18, 0, 0},
      {inf_d, inf_d, -inf_d, inf_d, 0, 0},
      {-2.3e-308, 5e-324, -inf_d, inf_d, 0, 0},
      {0., 24.1e87, -1.6e308, 24.1e87, 0, 0},
      {-5e-324, -5e-324, 5e-324, -5e-324, 0, 0}};

  const struct ExpectedResult_MSA3RF exp_res_fcaf = {0, 0};
  const struct ExpRes_32I exp_res_fcun_w[] = {
      {ones, ones, ones, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
  const struct ExpRes_64I exp_res_fcun_d[] = {{ones, ones}, {ones, 0}, {0, 0},
                                              {0, 0},       {0, 0},    {0, 0}};
  const struct ExpRes_32I exp_res_fceq_w[] = {
      {0, 0, 0, 0}, {0, ones, 0, 0}, {0, ones, 0, ones}};
  const struct ExpRes_64I exp_res_fceq_d[] = {{0, 0}, {0, 0},    {0, ones},
                                              {0, 0}, {0, ones}, {0, ones}};
  const struct ExpRes_32I exp_res_fcueq_w[] = {
      {ones, ones, ones, 0}, {0, ones, 0, 0}, {0, ones, 0, ones}};
  const struct ExpRes_64I exp_res_fcueq_d[] = {
      {ones, ones}, {ones, 0}, {0, ones}, {0, 0}, {0, ones}, {0, ones}};
  const struct ExpRes_32I exp_res_fclt_w[] = {
      {0, 0, 0, 0}, {0, 0, 0, ones}, {0, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fclt_d[] = {{0, 0},    {0, 0}, {0, 0},
                                              {0, ones}, {0, 0}, {ones, 0}};
  const struct ExpRes_32I exp_res_fcult_w[] = {
      {ones, ones, ones, 0}, {0, 0, 0, ones}, {0, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcult_d[] = {
      {ones, ones}, {ones, 0}, {0, 0}, {0, ones}, {0, 0}, {ones, 0}};
  const struct ExpRes_32I exp_res_fcle_w[] = {
      {0, 0, 0, 0}, {0, ones, 0, ones}, {0, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcle_d[] = {
      {0, 0}, {0, 0}, {0, ones}, {0, ones}, {0, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcule_w[] = {
      {ones, ones, ones, 0}, {0, ones, 0, ones}, {0, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcule_d[] = {
      {ones, ones}, {ones, 0}, {0, ones}, {0, ones}, {0, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcor_w[] = {
      {0, 0, 0, ones}, {ones, ones, ones, ones}, {ones, ones, ones, ones}};
  const struct ExpRes_64I exp_res_fcor_d[] = {{0, 0},       {0, ones},
                                              {ones, ones}, {ones, ones},
                                              {ones, ones}, {ones, ones}};
  const struct ExpRes_32I exp_res_fcune_w[] = {
      {ones, ones, ones, ones}, {ones, 0, ones, ones}, {ones, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcune_d[] = {{ones, ones}, {ones, ones},
                                               {ones, 0},    {ones, ones},
                                               {ones, 0},    {ones, 0}};
  const struct ExpRes_32I exp_res_fcne_w[] = {
      {0, 0, 0, ones}, {ones, 0, ones, ones}, {ones, 0, ones, 0}};
  const struct ExpRes_64I exp_res_fcne_d[] = {
      {0, 0}, {0, ones}, {ones, 0}, {ones, ones}, {ones, 0}, {ones, 0}};

#define TEST_FP_QUIET_COMPARE_W(instruction, src, exp_res)                    \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FP_QUIET_COMPARE_D(instruction, src, exp_res)                    \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FP_QUIET_COMPARE_W(fcaf_w, &tc_w[i], &exp_res_fcaf)
    TEST_FP_QUIET_COMPARE_W(fcun_w, &tc_w[i], &exp_res_fcun_w[i])
    TEST_FP_QUIET_COMPARE_W(fceq_w, &tc_w[i], &exp_res_fceq_w[i])
    TEST_FP_QUIET_COMPARE_W(fcueq_w, &tc_w[i], &exp_res_fcueq_w[i])
    TEST_FP_QUIET_COMPARE_W(fclt_w, &tc_w[i], &exp_res_fclt_w[i])
    TEST_FP_QUIET_COMPARE_W(fcult_w, &tc_w[i], &exp_res_fcult_w[i])
    TEST_FP_QUIET_COMPARE_W(fcle_w, &tc_w[i], &exp_res_fcle_w[i])
    TEST_FP_QUIET_COMPARE_W(fcule_w, &tc_w[i], &exp_res_fcule_w[i])
    TEST_FP_QUIET_COMPARE_W(fcor_w, &tc_w[i], &exp_res_fcor_w[i])
    TEST_FP_QUIET_COMPARE_W(fcune_w, &tc_w[i], &exp_res_fcune_w[i])
    TEST_FP_QUIET_COMPARE_W(fcne_w, &tc_w[i], &exp_res_fcne_w[i])
  }
  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    TEST_FP_QUIET_COMPARE_D(fcaf_d, &tc_d[i], &exp_res_fcaf)
    TEST_FP_QUIET_COMPARE_D(fcun_d, &tc_d[i], &exp_res_fcun_d[i])
    TEST_FP_QUIET_COMPARE_D(fceq_d, &tc_d[i], &exp_res_fceq_d[i])
    TEST_FP_QUIET_COMPARE_D(fcueq_d, &tc_d[i], &exp_res_fcueq_d[i])
    TEST_FP_QUIET_COMPARE_D(fclt_d, &tc_d[i], &exp_res_fclt_d[i])
    TEST_FP_QUIET_COMPARE_D(fcult_d, &tc_d[i], &exp_res_fcult_d[i])
    TEST_FP_QUIET_COMPARE_D(fcle_d, &tc_d[i], &exp_res_fcle_d[i])
    TEST_FP_QUIET_COMPARE_D(fcule_d, &tc_d[i], &exp_res_fcule_d[i])
    TEST_FP_QUIET_COMPARE_D(fcor_d, &tc_d[i], &exp_res_fcor_d[i])
    TEST_FP_QUIET_COMPARE_D(fcune_d, &tc_d[i], &exp_res_fcune_d[i])
    TEST_FP_QUIET_COMPARE_D(fcne_d, &tc_d[i], &exp_res_fcne_d[i])
  }
#undef TEST_FP_QUIET_COMPARE_W
#undef TEST_FP_QUIET_COMPARE_D
}

template <typename T>
inline const T* fadd_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] + src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fsub_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] - src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fmul_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] * src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fdiv_function(const T* src1, const T* src2, const T* src3,
                              T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = src1[i] / src2[i];
  }
  return dst;
}
template <typename T>
inline const T* fmadd_function(const T* src1, const T* src2, const T* src3,
                               T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = std::fma(src1[i], src2[i], src3[i]);
  }
  return dst;
}
template <typename T>
inline const T* fmsub_function(const T* src1, const T* src2, const T* src3,
                               T* dst) {
  for (uint64_t i = 0; i < kMSALanesByte / sizeof(T); i++) {
    dst[i] = std::fma(src1[i], -src2[i], src3[i]);
  }
  return dst;
}

TEST(MSA_floating_point_arithmetic) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      {0.3, -2.14e13f, inf_f, 0.f,                     // ws
       -inf_f, std::sqrt(8.e-26f), -23.e34, -2.14e9f,  // wt
       -1e30f, 4.6e12f, 0, 2.14e9f},                   // wd
      {3.4e38f, -1.2e-38f, 1e19f, -1e19f, 3.4e38f, 1.2e-38f, -1e19f, -1e-19f,
       3.4e38f, 1.2e-38f * 3, 3.4e38f, -4e19f},
      {-3e-31f, 3e10f, 1e25f, 123.f, 1e-14f, 1e-34f, 4e25f, 321.f, 3e-17f,
       2e-24f, 2.f, -123456.f}};

  const struct TestCaseMsa3RF_D tc_d[] = {
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {0.3, -2.14e103, -inf_d, std::sqrt(8.e-206), -1e30, 4.6e102},
      {inf_d, 0., -23.e304, -2.104e9, 0, 2.104e9},
      {3.4e307, -1.2e-307, 3.4e307, 1.2e-307, 3.4e307, 1.2e-307 * 3},
      {1e154, -1e154, -1e154, -1e-154, 2.9e38, -4e19},
      {-3e-301, 3e100, 1e-104, 1e-304, 3e-107, 2e-204},
      {1e205, 123., 4e205, 321., 2., -123456.}};

  struct ExpectedResult_MSA3RF dst_container;

#define FP_ARITHMETIC_DF_W(instr, function, src1, src2, src3)           \
  run_msa_3rf(                                                          \
      reinterpret_cast<const struct TestCaseMsa3RF*>(src1),             \
      reinterpret_cast<const struct ExpectedResult_MSA3RF*>(function(   \
          src1, src2, src3, reinterpret_cast<float*>(&dst_container))), \
      [](MacroAssembler& assm) { __ instr(w2, w0, w1); });

#define FP_ARITHMETIC_DF_D(instr, function, src1, src2, src3)            \
  run_msa_3rf(                                                           \
      reinterpret_cast<const struct TestCaseMsa3RF*>(src1),              \
      reinterpret_cast<const struct ExpectedResult_MSA3RF*>(function(    \
          src1, src2, src3, reinterpret_cast<double*>(&dst_container))), \
      [](MacroAssembler& assm) { __ instr(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    FP_ARITHMETIC_DF_W(fadd_w, fadd_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fsub_w, fsub_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmul_w, fmul_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fdiv_w, fdiv_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmadd_w, fmadd_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
    FP_ARITHMETIC_DF_W(fmsub_w, fmsub_function, &tc_w[i].ws_1, &tc_w[i].wt_1,
                       &tc_w[i].wd_1)
  }
  for (uint64_t i = 0; i < arraysize(tc_d); i++) {
    FP_ARITHMETIC_DF_D(fadd_d, fadd_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fsub_d, fsub_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmul_d, fmul_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fdiv_d, fdiv_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmadd_d, fmadd_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
    FP_ARITHMETIC_DF_D(fmsub_d, fmsub_function, &tc_d[i].ws_lo, &tc_d[i].wt_lo,
                       &tc_d[i].wd_lo)
  }
#undef FP_ARITHMETIC_DF_W
#undef FP_ARITHMETIC_DF_D
}

struct ExpRes_F {
  float exp_res_1;
  float exp_res_2;
  float exp_res_3;
  float exp_res_4;
};

struct ExpRes_D {
  double exp_res_1;
  double exp_res_2;
};

TEST(MSA_fmin_fmin_a_fmax_fmax_a) {
  if ((kArchVariant != kMips64r6) || !CpuFeatures::IsSupported(MIPS_SIMD))
    return;

  CcTest::InitializeVM();

  const float inf_f = std::numeric_limits<float>::infinity();
  const double inf_d = std::numeric_limits<double>::infinity();

  const struct TestCaseMsa3RF_F tc_w[] = {
      {0.3f, -2.14e13f, inf_f, -0.f,                    // ws
       -inf_f, -std::sqrt(8.e26f), -23.e34f, -2.14e9f,  // wt
       0, 0, 0, 0},                                     // wd
      {3.4e38f, 1.2e-41f, 1e19f, 1e19f,                 // ws
       3.4e38f, -1.1e-41f, -1e-42f, -1e29f,             // wt
       0, 0, 0, 0}};                                    // wd

  const struct TestCaseMsa3RF_D tc_d[] = {
      // ws_lo, ws_hi, wt_lo, wt_hi, wd_lo, wd_hi
      {0.3, -2.14e103, -inf_d, -std::sqrt(8e206), 0, 0},
      {inf_d, -0., -23e304, -2.14e90, 0, 0},
      {3.4e307, 1.2e-320, 3.4e307, -1.1e-320, 0, 0},
      {1e154, 1e154, -1e-321, -1e174, 0, 0}};

  const struct ExpRes_F exp_res_fmax_w[] = {{0.3f, -2.14e13f, inf_f, -0.f},
                                            {3.4e38f, 1.2e-41f, 1e19f, 1e19f}};
  const struct ExpRes_F exp_res_fmax_a_w[] = {
      {-inf_f, -std::sqrt(8e26f), inf_f, -2.14e9f},
      {3.4e38f, 1.2e-41f, 1e19f, -1e29f}};
  const struct ExpRes_F exp_res_fmin_w[] = {
      {-inf_f, -std::sqrt(8.e26f), -23e34f, -2.14e9f},
      {3.4e38f, -1.1e-41f, -1e-42f, -1e29f}};
  const struct ExpRes_F exp_res_fmin_a_w[] = {
      {0.3, -2.14e13f, -23.e34f, -0.f}, {3.4e38f, -1.1e-41f, -1e-42f, 1e19f}};

  const struct ExpRes_D exp_res_fmax_d[] = {
      {0.3, -2.14e103}, {inf_d, -0.}, {3.4e307, 1.2e-320}, {1e154, 1e154}};
  const struct ExpRes_D exp_res_fmax_a_d[] = {{-inf_d, -std::sqrt(8e206)},
                                              {inf_d, -2.14e90},
                                              {3.4e307, 1.2e-320},
                                              {1e154, -1e174}};
  const struct ExpRes_D exp_res_fmin_d[] = {{-inf_d, -std::sqrt(8e206)},
                                            {-23e304, -2.14e90},
                                            {3.4e307, -1.1e-320},
                                            {-1e-321, -1e174}};
  const struct ExpRes_D exp_res_fmin_a_d[] = {
      {0.3, -2.14e103}, {-23e304, -0.}, {3.4e307, -1.1e-320}, {-1e-321, 1e154}};

#define TEST_FP_MIN_MAX_W(instruction, src, exp_res)                          \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

#define TEST_FP_MIN_MAX_D(instruction, src, exp_res)                          \
  run_msa_3rf(reinterpret_cast<const struct TestCaseMsa3RF*>(src),            \
              reinterpret_cast<const struct ExpectedResult_MSA3RF*>(exp_res), \
              [](MacroAssembler& assm) { __ instruction(w2, w0, w1); });

  for (uint64_t i = 0; i < arraysize(tc_w); i++) {
    TEST_FP_MIN_MAX_W(fmax_w, &tc_w[i], &exp_res_fmax_w[i])
    TEST_FP_MIN_MAX_W(fmax_a_w, &tc_w[i], &exp_res_fmax_a_w[i])
    TEST_FP_MIN_MAX_W(fmin_w, &tc_w[
"""


```