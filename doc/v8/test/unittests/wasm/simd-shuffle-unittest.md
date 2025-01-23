Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:** The filename `simd-shuffle-unittest.cc` immediately signals that this code is testing functionality related to SIMD (Single Instruction, Multiple Data) shuffles in the V8 JavaScript engine. The "unittest" part confirms it's focused on isolated testing of specific functions.

2. **Scan for Key Components:** Look for the main building blocks:
    * **Includes:**  `#include "src/wasm/simd-shuffle.h"` is crucial. It tells us the code under test is likely defined in `simd-shuffle.h`. Other includes like `"test/unittests/test-utils.h"` and `"testing/gmock-support.h"` are standard for V8 unit tests, providing testing infrastructure.
    * **Namespaces:** `v8::internal::wasm` indicates this code is part of V8's internal WebAssembly implementation.
    * **Test Fixture:** The `SimdShuffleTest` class inheriting from `::testing::Test` is the standard way to organize tests in Google Test. This tells us we'll have multiple test cases within this fixture.
    * **Helper Functions/Types:** Notice the `Shuffle` and `TestShuffle` types, and the static methods within `SimdShuffleTest`. These are tools to facilitate testing the `SimdShuffle` functionality. The `CanonicalizeShuffle` function stands out as potentially important.
    * **Individual Tests:**  The `TEST_F` macros define the actual test cases, like `CanonicalizeShuffle`, `TryMatchIdentity`, etc. Each test focuses on a specific aspect of the shuffle logic.
    * **Assertions:**  Look for `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_THAT`. These are the core of the tests, verifying expected behavior.
    * **Conditional Compilation:** The `#ifdef V8_TARGET_ARCH_X64` blocks indicate platform-specific tests, likely related to x64-specific SIMD instructions.

3. **Analyze Individual Tests (Iterative Approach):**  Go through each `TEST_F` case and try to understand its purpose:
    * **`CanonicalizeShuffle`:**  This test seems to verify the `CanonicalizeShuffle` function. It tests scenarios with and without "inputs equal" (which seems to relate to swizzling). The `TestShuffle` struct helps organize inputs and expected outputs.
    * **`TryMatchIdentity`:** Checks if a shuffle is the identity (no change).
    * **`TryMatchSplat`:**  Tests for splatting (duplicating a single lane across the vector). The `<LANES>` template parameter is a hint about different vector sizes.
    * **`TryMatchConcat`:**  Looks for patterns where the output is a concatenation of parts of the input.
    * **`TryMatch32x4Shuffle`, `TryMatch32x8Shuffle`, `TryMatch16x8Shuffle`:** These likely check for specific shuffling patterns related to different data types (32-bit, 16-bit) within the SIMD vector.
    * **`TryMatch32x4Reverse`, `TryMatch32x4OneLaneSwizzle`:** Test for specific, named shuffle operations.
    * **`TryMatchBlend`:** Checks if the shuffle is a blend (selecting elements from the two input vectors).
    * **`PairwiseReduce`, `UpperToLowerReduce`:** Test for specific reduction patterns.
    * **`Shuffle64x2`:** Tests shuffles specific to 64-bit lanes.
    * **`CanonicalMatchers`:**  Likely tests a comprehensive set of known canonical shuffles.
    * **`PackShuffle4`, `PackBlend8`, `PackBlend4`, `Pack4Lanes`, `Pack16Lanes`:** These seem to test functions that pack shuffle information into smaller data types, possibly for instruction encoding.
    * **`TryMatchVpshufd`, `TryMatchShufps256`:**  Platform-specific tests for x64 SIMD instructions.

4. **Look for Connections to JavaScript/WebAssembly:**  The `wasm` namespace is the strongest indicator. SIMD operations in WebAssembly have direct mappings to JavaScript's SIMD API (`Float32x4`, `Int32x4`, etc.). The concept of "shuffling" is fundamental to both.

5. **Infer Functionality:** Based on the test names and the operations being checked, deduce the purpose of the tested functions in `simd-shuffle.h`. For example, `CanonicalizeShuffle` likely aims to put shuffles into a standard form for easier comparison or optimization. The `TryMatch...` functions likely try to recognize specific shuffle patterns.

6. **Consider User Errors:** Think about common mistakes developers might make when working with SIMD shuffles. Incorrect lane indices, misunderstanding the behavior of specific shuffle operations, or trying to perform invalid shuffles are possibilities.

7. **Structure the Output:** Organize the findings logically, addressing each part of the prompt (functionality, Torque, JavaScript relationship, logic, errors). Use clear and concise language. Provide illustrative JavaScript examples where relevant.

8. **Review and Refine:**  Read through the analysis to ensure accuracy and completeness. Check if all parts of the prompt have been addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this is about optimizing SIMD operations."  **Refinement:** "Yes, but more specifically, it's about *canonicalizing* and *recognizing* different shuffle patterns, which is likely a step in optimization or code generation."
* **Initial thought:** "The `Pack...` functions are confusing." **Refinement:** "They are likely related to how shuffle operations are encoded or represented internally, maybe for instruction selection."
* **When seeing the `#ifdef` blocks:** "Ah, this means some of the logic is specific to certain architectures. I should highlight that."
* **While looking at the `CanonicalizeShuffle` tests:** "The 'inputs_equal' flag is interesting. It probably distinguishes between general shuffles and swizzles where the input vectors are the same."

By following these steps, combining code examination with reasoning and domain knowledge (SIMD, testing), a comprehensive understanding of the unittest's functionality can be achieved.
`v8/test/unittests/wasm/simd-shuffle-unittest.cc` 是一个 V8 JavaScript 引擎的 C++ 单元测试文件。它的主要功能是测试 WebAssembly SIMD (Single Instruction, Multiple Data) 操作中的 shuffle (重组) 功能。

以下是该文件的详细功能列表：

1. **测试 SIMD shuffle 操作的规范化:**
   - `CanonicalizeShuffle` 函数用于将 SIMD shuffle 操作的表示形式规范化。这包括处理输入操作数相同的情况 (swizzle) 以及需要交换操作数的情况。
   - 测试用例验证了不同 shuffle 模式的规范化结果，包括恒等变换、需要交换的情况以及当输入相等时的 swizzle 规范化。

2. **测试识别特定的 SIMD shuffle 模式:**
   - 文件中定义了多个 `TryMatch...` 函数，用于尝试将给定的 shuffle 模式与已知的特定模式进行匹配。
   - 这些模式包括：
     - `TryMatchIdentity`: 识别恒等变换 (不改变向量元素顺序)。
     - `TryMatchSplat`: 识别将单个通道的值复制到所有通道。
     - `TryMatchConcat`: 识别将两个向量的一部分连接在一起的模式。
     - `TryMatch32x4Shuffle`, `TryMatch32x8Shuffle`, `TryMatch16x8Shuffle`: 识别针对不同数据类型（32 位、16 位）的特定 shuffle 模式。
     - `TryMatch32x4Reverse`: 识别反转 32 位通道顺序的模式。
     - `TryMatch32x4OneLaneSwizzle`: 识别在一个 32 位通道内进行 swizzle 的模式。
     - `TryMatchBlend`: 识别从两个输入向量中选择元素的混合模式。
     - `TryMatch64x2Shuffle`: 识别针对 64 位通道的 shuffle 模式。
     - `TryMatch64x2Reduce`, `TryMatch32x4PairwiseReduce`, `TryMatch32x4UpperToLowerReduce`, `TryMatch16x8UpperToLowerReduce`, `TryMatch8x16UpperToLowerReduce`: 识别不同的归约操作模式。
   - 测试用例使用不同的 shuffle 模式作为输入，并验证 `TryMatch...` 函数是否能够正确识别它们。

3. **测试将 shuffle 模式打包成更小的表示:**
   - `PackShuffle4`, `PackBlend8`, `PackBlend4`, `Pack4Lanes`, `Pack16Lanes` 等函数用于将 shuffle 信息打包成更紧凑的格式，例如位掩码或整数。
   - 测试用例验证了这些打包函数对于不同的 shuffle 模式是否产生了预期的结果。

4. **测试特定架构的 SIMD shuffle 指令匹配 (例如 x64):**
   - `#ifdef V8_TARGET_ARCH_X64` 块内的测试用例专门针对 x64 架构。
   - `TryMatchVpshufd` 和 `TryMatchShufps256` 函数尝试将 shuffle 模式与 x64 上的 `vpshufd` 和 `shufps` 指令匹配。
   - 这些测试验证了在 x64 平台上，特定的 shuffle 模式是否能够映射到相应的硬件指令。

**如果 `v8/test/unittests/wasm/simd-shuffle-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但根据你提供的文件名，它以 `.cc` 结尾，因此它是一个 **C++** 源代码文件，而不是 Torque 文件。Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 Javascript 的功能关系:**

`simd-shuffle-unittest.cc` 测试的 SIMD shuffle 功能直接对应于 JavaScript 中的 SIMD API。JavaScript 提供了诸如 `Float32x4`, `Int32x4`, `Float64x2` 等对象，这些对象表示 SIMD 向量。这些对象上的一些方法执行 shuffle 操作，允许重新排列向量内的元素。

**Javascript 举例说明:**

```javascript
// 假设我们有一个 Float32x4 向量
const a = Float32x4(1.0, 2.0, 3.0, 4.0);
const b = Float32x4(5.0, 6.0, 7.0, 8.0);

// 使用 shuffle 方法重新排列元素
// 例如，将 a 和 b 的元素交错
const shuffled = Float32x4.shuffle(a, b, 0, 4, 1, 5); // 相当于从 [a0, a1, a2, a3, b0, b1, b2, b3] 中选择索引 0, 4, 1, 5 的元素
console.log(shuffled); // 输出: Float32x4(1, 5, 2, 6)

// 另一个例子，在单个向量内部进行 swizzle (一种特殊的 shuffle)
const swizzled = a.shuffle(0, 0, 1, 1); // 复制 a 的前两个元素
console.log(swizzled); // 输出: Float32x4(1, 1, 2, 2)
```

`v8/test/unittests/wasm/simd-shuffle-unittest.cc` 中的测试用例旨在验证 V8 的 WebAssembly 实现是否正确地执行了这些 shuffle 操作，确保 WebAssembly 代码中的 SIMD shuffle 指令能够按照预期的方式工作，并且与 JavaScript 的 SIMD API 行为一致。

**代码逻辑推理 (假设输入与输出):**

假设我们测试 `TryMatch32x4Reverse` 函数，它旨在识别反转 32 位通道顺序的 shuffle 模式。

**假设输入:**

```c++
SimdShuffleTest::Shuffle<kSimd128Size> shuffle =
    {{12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3}};
```

这个 shuffle 模式表示：
- 输出的第 0-3 字节来自输入的第 12-15 字节 (第 3 个 32 位通道)
- 输出的第 4-7 字节来自输入的第 8-11 字节 (第 2 个 32 位通道)
- 输出的第 8-11 字节来自输入的第 4-7 字节 (第 1 个 32 位通道)
- 输出的第 12-15 字节来自输入的第 0-3 字节 (第 0 个 32 位通道)

**预期输出:**

`TryMatch32x4Reverse` 函数应该返回 `true`，因为它匹配了反转 32 位通道顺序的模式。

**涉及用户常见的编程错误:**

1. **错误的 shuffle 索引:** 用户在 JavaScript 或 WebAssembly 中进行 shuffle 操作时，可能会提供错误的索引，导致非预期的元素排列。

   **JavaScript 示例:**

   ```javascript
   const vec = Float32x4(1, 2, 3, 4);
   const wrongShuffle = vec.shuffle(0, 1, 5, 2); // 索引 5 超出范围 (0-3)
   // 这会导致错误或未定义的行为，具体取决于引擎的实现。
   ```

2. **混淆 shuffle 和 swizzle:** 用户可能不清楚 shuffle 和 swizzle 之间的区别。Swizzle 是在单个向量内部进行元素重排，而 shuffle 可以混合来自两个向量的元素。

   **JavaScript 示例:**

   ```javascript
   const a = Float32x4(1, 2, 3, 4);
   const b = Float32x4(5, 6, 7, 8);

   // 错误地使用 shuffle 期望得到 swizzle 的结果
   const incorrectShuffle = Float32x4.shuffle(a, a, 0, 1, 2, 3); // 这仍然是一个 shuffle，尽管输入相同
   const correctSwizzle = a.shuffle(0, 1, 2, 3);
   ```

3. **对齐问题:** 在某些底层实现中，SIMD 操作可能对数据对齐有要求。如果用户提供的输入数据未正确对齐，可能会导致性能下降或错误。虽然 JavaScript 抽象了大部分对齐问题，但在 WebAssembly 中使用内存操作时需要注意。

4. **误解特定 shuffle 操作的含义:**  不同的 shuffle 操作有特定的含义（例如，interleave, transpose）。用户可能不理解这些操作的具体行为，导致使用了错误的 shuffle 指令。

`v8/test/unittests/wasm/simd-shuffle-unittest.cc` 中的测试用例有助于确保 V8 引擎能够正确地处理各种 SIMD shuffle 操作，从而帮助开发者避免这些常见的编程错误。这些测试覆盖了不同的 shuffle 模式和场景，确保了引擎在处理这些操作时的正确性和一致性。

### 提示词
```
这是目录为v8/test/unittests/wasm/simd-shuffle-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/simd-shuffle-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/simd-shuffle.h"

#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"

using ::testing::ElementsAre;

namespace v8 {
namespace internal {
namespace wasm {
// Helper to make calls to private wasm shuffle functions.
class SimdShuffleTest : public ::testing::Test {
 public:
  template <int Size, typename = std::enable_if_t<Size == kSimd128Size ||
                                                  Size == kSimd256Size>>
  using Shuffle = std::array<uint8_t, Size>;

  template <int Size, typename = std::enable_if_t<Size == kSimd128Size ||
                                                  Size == kSimd256Size>>
  struct TestShuffle {
    Shuffle<Size> non_canonical;
    Shuffle<Size> canonical;
    bool needs_swap;
    bool is_swizzle;
  };

  // Call testing members in wasm.
  static void CanonicalizeShuffle(bool inputs_equal,
                                  Shuffle<kSimd128Size>* shuffle,
                                  bool* needs_swap, bool* is_swizzle) {
    SimdShuffle::CanonicalizeShuffle(inputs_equal, &(*shuffle)[0], needs_swap,
                                     is_swizzle);
  }

  static bool TryMatchIdentity(const Shuffle<kSimd128Size>& shuffle) {
    return SimdShuffle::TryMatchIdentity(&shuffle[0]);
  }
  template <int LANES>
  static bool TryMatchSplat(const Shuffle<kSimd128Size>& shuffle, int* index) {
    return SimdShuffle::TryMatchSplat<LANES>(&shuffle[0], index);
  }
  static bool TryMatch64x2Shuffle(const Shuffle<kSimd128Size>& shuffle,
                                  uint8_t* shuffle64x2) {
    return SimdShuffle::TryMatch64x2Shuffle(&shuffle[0], shuffle64x2);
  }
  static bool TryMatch32x4Shuffle(const Shuffle<kSimd128Size>& shuffle,
                                  uint8_t* shuffle32x4) {
    return SimdShuffle::TryMatch32x4Shuffle(&shuffle[0], shuffle32x4);
  }
  static bool TryMatch32x8Shuffle(const Shuffle<kSimd256Size>& shuffle,
                                  uint8_t* shuffle32x8) {
    return SimdShuffle::TryMatch32x8Shuffle(&shuffle[0], shuffle32x8);
  }
  static bool TryMatch32x4Reverse(const uint8_t* shuffle32x4) {
    return SimdShuffle::TryMatch32x4Reverse(shuffle32x4);
  }
  static bool TryMatch32x4OneLaneSwizzle(const uint8_t* shuffle32x4,
                                         uint8_t* from, uint8_t* to) {
    return SimdShuffle::TryMatch32x4OneLaneSwizzle(shuffle32x4, from, to);
  }
  static bool TryMatch16x8Shuffle(const Shuffle<kSimd128Size>& shuffle,
                                  uint8_t* shuffle16x8) {
    return SimdShuffle::TryMatch16x8Shuffle(&shuffle[0], shuffle16x8);
  }
  static bool TryMatchConcat(const Shuffle<kSimd128Size>& shuffle,
                             uint8_t* offset) {
    return SimdShuffle::TryMatchConcat(&shuffle[0], offset);
  }
  static bool TryMatchBlend(const Shuffle<kSimd128Size>& shuffle) {
    return SimdShuffle::TryMatchBlend(&shuffle[0]);
  }
#ifdef V8_TARGET_ARCH_X64
  static bool TryMatchVpshufd(const uint8_t* shuffle32x8, uint8_t* control) {
    return SimdShuffle::TryMatchVpshufd(shuffle32x8, control);
  }
  static bool TryMatchShufps256(const uint8_t* shuffle32x8, uint8_t* control) {
    return SimdShuffle::TryMatchShufps256(shuffle32x8, control);
  }
#endif  // V8_TARGET_ARCH_X64
};

template <int Size, typename = std::enable_if_t<Size == kSimd128Size ||
                                                Size == kSimd256Size>>
bool operator==(const SimdShuffleTest::Shuffle<Size>& a,
                const SimdShuffleTest::Shuffle<Size>& b) {
  for (int i = 0; i < Size; ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

TEST_F(SimdShuffleTest, CanonicalizeShuffle) {
  const bool kInputsEqual = true;
  const bool kNeedsSwap = true;
  const bool kIsSwizzle = true;

  bool needs_swap;
  bool is_swizzle;

  // Test canonicalization driven by input shuffle.
  TestShuffle<kSimd128Size> test_shuffles[] = {
      // Identity is canonical.
      {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       !kNeedsSwap,
       kIsSwizzle},
      // Non-canonical identity requires a swap.
      {{{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}},
       {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       kNeedsSwap,
       kIsSwizzle},
      // General shuffle, canonical is unchanged.
      {{{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}},
       {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}},
       !kNeedsSwap,
       !kIsSwizzle},
      // Non-canonical shuffle requires a swap.
      {{{16, 0, 17, 1, 18, 2, 19, 3, 20, 4, 21, 5, 22, 6, 23, 7}},
       {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}},
       kNeedsSwap,
       !kIsSwizzle},
  };
  for (size_t i = 0; i < arraysize(test_shuffles); ++i) {
    Shuffle<kSimd128Size> shuffle = test_shuffles[i].non_canonical;
    CanonicalizeShuffle(!kInputsEqual, &shuffle, &needs_swap, &is_swizzle);
    EXPECT_EQ(shuffle, test_shuffles[i].canonical);
    EXPECT_EQ(needs_swap, test_shuffles[i].needs_swap);
    EXPECT_EQ(is_swizzle, test_shuffles[i].is_swizzle);
  }

  // Test canonicalization when inputs are equal (explicit swizzle).
  TestShuffle<kSimd128Size> test_swizzles[] = {
      // Identity is canonical.
      {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       !kNeedsSwap,
       kIsSwizzle},
      // Non-canonical identity requires a swap.
      {{{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}},
       {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
       !kNeedsSwap,
       kIsSwizzle},
      // Canonicalized to swizzle.
      {{{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}},
       {{0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7}},
       !kNeedsSwap,
       kIsSwizzle},
      // Canonicalized to swizzle.
      {{{16, 0, 17, 1, 18, 2, 19, 3, 20, 4, 21, 5, 22, 6, 23, 7}},
       {{0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7}},
       !kNeedsSwap,
       kIsSwizzle},
  };
  for (size_t i = 0; i < arraysize(test_swizzles); ++i) {
    Shuffle<kSimd128Size> shuffle = test_swizzles[i].non_canonical;
    CanonicalizeShuffle(kInputsEqual, &shuffle, &needs_swap, &is_swizzle);
    EXPECT_EQ(shuffle, test_swizzles[i].canonical);
    EXPECT_EQ(needs_swap, test_swizzles[i].needs_swap);
    EXPECT_EQ(is_swizzle, test_swizzles[i].is_swizzle);
  }
}

TEST_F(SimdShuffleTest, TryMatchIdentity) {
  // Match shuffle that returns first source operand.
  EXPECT_TRUE(TryMatchIdentity(
      {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}));
  // The non-canonicalized identity shuffle doesn't match.
  EXPECT_FALSE(TryMatchIdentity(
      {{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}}));
  // Even one lane out of place is not an identity shuffle.
  EXPECT_FALSE(TryMatchIdentity(
      {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 31}}));
}

TEST_F(SimdShuffleTest, TryMatchSplat) {
  int index;
  // All lanes from the same 32 bit source lane.
  EXPECT_TRUE(TryMatchSplat<4>(
      {{4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7}}, &index));
  EXPECT_EQ(1, index);
  // It shouldn't match for other vector shapes.
  EXPECT_FALSE(TryMatchSplat<8>(
      {{4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7}}, &index));
  EXPECT_FALSE(TryMatchSplat<16>(
      {{4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7, 4, 5, 6, 7}}, &index));
  // All lanes from the same 16 bit source lane.
  EXPECT_TRUE(TryMatchSplat<8>(
      {{16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17}},
      &index));
  EXPECT_EQ(8, index);
  // It shouldn't match for other vector shapes.
  EXPECT_FALSE(TryMatchSplat<4>(
      {{16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17}},
      &index));
  EXPECT_FALSE(TryMatchSplat<16>(
      {{16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17, 16, 17}},
      &index));
  // All lanes from the same 8 bit source lane.
  EXPECT_TRUE(TryMatchSplat<16>(
      {{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}}, &index));
  EXPECT_EQ(7, index);
  // It shouldn't match for other vector shapes.
  EXPECT_FALSE(TryMatchSplat<4>(
      {{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}}, &index));
  EXPECT_FALSE(TryMatchSplat<8>(
      {{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}}, &index));
}

TEST_F(SimdShuffleTest, TryMatchConcat) {
  uint8_t offset;
  // Ascending indices, jump at end to same input (concatenating swizzle).
  EXPECT_TRUE(TryMatchConcat(
      {{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2}}, &offset));
  EXPECT_EQ(3, offset);
  // Ascending indices, jump at end to other input (concatenating shuffle).
  EXPECT_TRUE(TryMatchConcat(
      {{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}, &offset));
  EXPECT_EQ(4, offset);

  // Shuffles that should not match:
  // Ascending indices, but jump isn't at end/beginning.
  EXPECT_FALSE(TryMatchConcat(
      {{3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 1, 2, 3, 4, 5, 6}}, &offset));
  // Ascending indices, but multiple jumps.
  EXPECT_FALSE(TryMatchConcat(
      {{0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3}}, &offset));
}

TEST_F(SimdShuffleTest, TryMatch32x4Shuffle) {
  uint8_t shuffle32x4[4];
  // Match if each group of 4 bytes is from the same 32 bit lane.
  EXPECT_TRUE(TryMatch32x4Shuffle(
      {{12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 16, 17, 18, 19}},
      shuffle32x4));
  EXPECT_EQ(3, shuffle32x4[0]);
  EXPECT_EQ(2, shuffle32x4[1]);
  EXPECT_EQ(1, shuffle32x4[2]);
  EXPECT_EQ(4, shuffle32x4[3]);
  // Bytes must be in order in the 32 bit lane.
  EXPECT_FALSE(TryMatch32x4Shuffle(
      {{12, 13, 14, 14, 8, 9, 10, 11, 4, 5, 6, 7, 16, 17, 18, 19}},
      shuffle32x4));
  // Each group must start with the first byte in the 32 bit lane.
  EXPECT_FALSE(TryMatch32x4Shuffle(
      {{13, 14, 15, 12, 8, 9, 10, 11, 4, 5, 6, 7, 16, 17, 18, 19}},
      shuffle32x4));
}

TEST_F(SimdShuffleTest, TryMatch32x8Shuffle) {
  uint8_t shuffle32x8[8];
  // Match if each group of 4 bytes is from the same 32 bit lane.
  EXPECT_TRUE(TryMatch32x8Shuffle(
      {{12, 13, 14, 15, 8,  9,  10, 11, 4,  5,  6,  7,  16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,  1,  2,  3}},
      shuffle32x8));
  EXPECT_EQ(3, shuffle32x8[0]);
  EXPECT_EQ(2, shuffle32x8[1]);
  EXPECT_EQ(1, shuffle32x8[2]);
  EXPECT_EQ(4, shuffle32x8[3]);
  EXPECT_EQ(5, shuffle32x8[4]);
  EXPECT_EQ(6, shuffle32x8[5]);
  EXPECT_EQ(7, shuffle32x8[6]);
  EXPECT_EQ(0, shuffle32x8[7]);
  // Bytes must be in order in the 32 bit lane.
  EXPECT_FALSE(TryMatch32x8Shuffle(
      {{12, 13, 14, 14, 8,  9,  10, 11, 4,  5,  6,  7,  16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,  1,  2,  3}},
      shuffle32x8));
  // Each group must start with the first byte in the 32 bit lane.
  EXPECT_FALSE(TryMatch32x8Shuffle(
      {{13, 14, 15, 12, 8,  9,  10, 11, 4,  5,  6,  7,  16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,  1,  2,  3}},
      shuffle32x8));
}

TEST_F(SimdShuffleTest, TryMatch32x4Reverse) {
  Shuffle<kSimd128Size> low_rev = {12, 13, 14, 15, 8, 9, 10, 11,
                                   4,  5,  6,  7,  0, 1, 2,  3};
  std::array<uint8_t, 4> shuffle32x4;
  // low
  EXPECT_TRUE(TryMatch32x4Shuffle(low_rev, shuffle32x4.data()));
  EXPECT_EQ(3, shuffle32x4[0]);
  EXPECT_EQ(2, shuffle32x4[1]);
  EXPECT_EQ(1, shuffle32x4[2]);
  EXPECT_EQ(0, shuffle32x4[3]);
  EXPECT_TRUE(TryMatch32x4Reverse(shuffle32x4.data()));
  EXPECT_EQ(SimdShuffle::TryMatchCanonical(low_rev),
            SimdShuffle::kS32x4Reverse);

  // high
  Shuffle<kSimd128Size> high_rev = {28, 29, 30, 31, 24, 25, 26, 27,
                                    20, 21, 22, 23, 16, 17, 18, 19};
  EXPECT_TRUE(TryMatch32x4Shuffle(high_rev, shuffle32x4.data()));
  EXPECT_EQ(7, shuffle32x4[0]);
  EXPECT_EQ(6, shuffle32x4[1]);
  EXPECT_EQ(5, shuffle32x4[2]);
  EXPECT_EQ(4, shuffle32x4[3]);

  bool needs_swap = false;
  bool is_swizzle = false;
  CanonicalizeShuffle(false, &high_rev, &needs_swap, &is_swizzle);
  EXPECT_TRUE(needs_swap);
  EXPECT_TRUE(is_swizzle);
  EXPECT_TRUE(TryMatch32x4Shuffle(high_rev, shuffle32x4.data()));
  EXPECT_TRUE(TryMatch32x4Reverse(shuffle32x4.data()));
  EXPECT_EQ(SimdShuffle::TryMatchCanonical(high_rev),
            SimdShuffle::kS32x4Reverse);
}

TEST_F(SimdShuffleTest, TryMatch32x4OneLaneSwizzle) {
  uint8_t shuffle32x4[4];
  uint8_t from = 0;
  uint8_t to = 0;
  // low
  EXPECT_TRUE(TryMatch32x4Shuffle(
      {{12, 13, 14, 15, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
      shuffle32x4));
  EXPECT_EQ(3, shuffle32x4[0]);
  EXPECT_EQ(1, shuffle32x4[1]);
  EXPECT_EQ(2, shuffle32x4[2]);
  EXPECT_EQ(3, shuffle32x4[3]);
  EXPECT_TRUE(TryMatch32x4OneLaneSwizzle(shuffle32x4, &from, &to));
  EXPECT_EQ(from, 3);
  EXPECT_EQ(to, 0);

  // high
  Shuffle<kSimd128Size> high_one = {16, 17, 18, 19, 20, 21, 22, 23,
                                    20, 21, 22, 23, 28, 29, 30, 31};
  EXPECT_TRUE(TryMatch32x4Shuffle(high_one, shuffle32x4));
  EXPECT_EQ(4, shuffle32x4[0]);
  EXPECT_EQ(5, shuffle32x4[1]);
  EXPECT_EQ(5, shuffle32x4[2]);
  EXPECT_EQ(7, shuffle32x4[3]);

  bool needs_swap = false;
  bool is_swizzle = false;
  CanonicalizeShuffle(false, &high_one, &needs_swap, &is_swizzle);
  EXPECT_TRUE(needs_swap);
  EXPECT_TRUE(is_swizzle);
  EXPECT_TRUE(TryMatch32x4Shuffle(high_one, shuffle32x4));
  EXPECT_TRUE(TryMatch32x4OneLaneSwizzle(shuffle32x4, &from, &to));
  EXPECT_EQ(from, 1);
  EXPECT_EQ(to, 2);
}

TEST_F(SimdShuffleTest, TryMatch16x8Shuffle) {
  uint8_t shuffle16x8[8];
  // Match if each group of 2 bytes is from the same 16 bit lane.
  EXPECT_TRUE(TryMatch16x8Shuffle(
      {{12, 13, 30, 31, 8, 9, 26, 27, 4, 5, 22, 23, 16, 17, 2, 3}},
      shuffle16x8));
  EXPECT_EQ(6, shuffle16x8[0]);
  EXPECT_EQ(15, shuffle16x8[1]);
  EXPECT_EQ(4, shuffle16x8[2]);
  EXPECT_EQ(13, shuffle16x8[3]);
  EXPECT_EQ(2, shuffle16x8[4]);
  EXPECT_EQ(11, shuffle16x8[5]);
  EXPECT_EQ(8, shuffle16x8[6]);
  EXPECT_EQ(1, shuffle16x8[7]);
  // Bytes must be in order in the 16 bit lane.
  EXPECT_FALSE(TryMatch16x8Shuffle(
      {{12, 13, 30, 30, 8, 9, 26, 27, 4, 5, 22, 23, 16, 17, 2, 3}},
      shuffle16x8));
  // Each group must start with the first byte in the 16 bit lane.
  EXPECT_FALSE(TryMatch16x8Shuffle(
      {{12, 13, 31, 30, 8, 9, 26, 27, 4, 5, 22, 23, 16, 17, 2, 3}},
      shuffle16x8));
}

TEST_F(SimdShuffleTest, TryMatchBlend) {
  // Match if each byte remains in place.
  EXPECT_TRUE(TryMatchBlend(
      {{0, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31}}));
  // Identity is a blend.
  EXPECT_TRUE(
      TryMatchBlend({{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}));
  // Even one lane out of place is not a blend.
  EXPECT_FALSE(TryMatchBlend(
      {{1, 17, 2, 19, 4, 21, 6, 23, 8, 25, 10, 27, 12, 29, 14, 31}}));
}

TEST_F(SimdShuffleTest, PairwiseReduce) {
  uint8_t shuffle64x2[2];
  EXPECT_TRUE(TryMatch64x2Shuffle(
      {{8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7}}, shuffle64x2));
  EXPECT_TRUE(SimdShuffle::TryMatch64x2Reduce(shuffle64x2));

  constexpr uint8_t pairwise_32x4[] = {4,  5,  6,  7,  0, 1, 2, 3,
                                       12, 13, 14, 15, 0, 1, 2, 3};
  constexpr uint8_t pairwise_32x2[] = {8, 9, 10, 11, 0, 1, 2, 3,
                                       0, 1, 2,  3,  0, 1, 2, 3};
  EXPECT_TRUE(
      SimdShuffle::TryMatch32x4PairwiseReduce(pairwise_32x4, pairwise_32x2));
}

TEST_F(SimdShuffleTest, UpperToLowerReduce) {
  constexpr uint8_t upper_to_lower_32x4[] = {8, 9, 10, 11, 12, 13, 14, 15,
                                             0, 1, 2,  3,  0,  1,  2,  3};
  constexpr uint8_t upper_to_lower_32x2[] = {4, 5, 6, 7, 0, 1, 2, 3,
                                             0, 1, 2, 3, 0, 1, 2, 3};
  EXPECT_TRUE(SimdShuffle::TryMatch32x4UpperToLowerReduce(upper_to_lower_32x4,
                                                          upper_to_lower_32x2));

  constexpr uint8_t upper_to_lower_16x8[] = {8, 9, 10, 11, 12, 13, 14, 15, 0,
                                             1, 0, 1,  0,  1,  0,  1,  0};
  constexpr uint8_t upper_to_lower_16x4[] = {4, 5, 6, 7, 0, 1, 0, 1,
                                             0, 1, 0, 1, 0, 1, 0, 1};
  constexpr uint8_t upper_to_lower_16x2[] = {2, 3, 0, 1, 0, 1, 0, 1,
                                             0, 1, 0, 1, 0, 1, 0, 1};
  EXPECT_TRUE(SimdShuffle::TryMatch16x8UpperToLowerReduce(
      upper_to_lower_16x8, upper_to_lower_16x4, upper_to_lower_16x2));

  constexpr uint8_t upper_to_lower_8x16[] = {8, 9, 10, 11, 12, 13, 14, 15, 0,
                                             1, 0, 1,  0,  1,  0,  1,  0};
  constexpr uint8_t upper_to_lower_8x8[] = {4, 5, 6, 7, 0, 1, 0, 1,
                                            0, 1, 0, 1, 0, 1, 0, 1};
  constexpr uint8_t upper_to_lower_8x4[] = {2, 3, 0, 1, 0, 1, 0, 1,
                                            0, 1, 0, 1, 0, 1, 0, 1};
  constexpr uint8_t upper_to_lower_8x2[] = {1, 0, 0, 1, 0, 1, 0, 1,
                                            0, 1, 0, 1, 0, 1, 0, 1};
  EXPECT_TRUE(SimdShuffle::TryMatch8x16UpperToLowerReduce(
      upper_to_lower_8x16, upper_to_lower_8x8, upper_to_lower_8x4,
      upper_to_lower_8x2));
}

TEST_F(SimdShuffleTest, Shuffle64x2) {
  constexpr uint8_t identity_64x2[] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};
  std::array<uint8_t, 8> shuffle64x2;
  EXPECT_TRUE(
      SimdShuffle::TryMatch64x2Shuffle(identity_64x2, shuffle64x2.data()));
  EXPECT_EQ(shuffle64x2[0], 0);
  EXPECT_EQ(shuffle64x2[1], 1);

  constexpr uint8_t rev_64x2[] = {8, 9, 10, 11, 12, 13, 14, 15,
                                  0, 1, 2,  3,  4,  5,  6,  7};
  EXPECT_TRUE(SimdShuffle::TryMatch64x2Shuffle(rev_64x2, shuffle64x2.data()));
  EXPECT_EQ(shuffle64x2[0], 1);
  EXPECT_EQ(shuffle64x2[1], 0);

  constexpr uint8_t dup0_64x2[] = {0, 1, 2, 3, 4, 5, 6, 7,
                                   0, 1, 2, 3, 4, 5, 6, 7};
  EXPECT_TRUE(SimdShuffle::TryMatch64x2Shuffle(dup0_64x2, shuffle64x2.data()));
  EXPECT_EQ(shuffle64x2[0], 0);
  EXPECT_EQ(shuffle64x2[1], 0);

  constexpr uint8_t dup1_64x2[] = {8, 9, 10, 11, 12, 13, 14, 15,
                                   8, 9, 10, 11, 12, 13, 14, 15};
  EXPECT_TRUE(SimdShuffle::TryMatch64x2Shuffle(dup1_64x2, shuffle64x2.data()));
  EXPECT_EQ(shuffle64x2[0], 1);
  EXPECT_EQ(shuffle64x2[1], 1);
}

using ShuffleMap = std::unordered_map<SimdShuffle::CanonicalShuffle,
                                      const std::array<uint8_t, kSimd128Size>>;

ShuffleMap test_shuffles = {
    {SimdShuffle::kIdentity,
     {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}},
    {SimdShuffle::kUnknown,
     {{0, 1, 2, 3, 16, 17, 18, 19, 16, 17, 18, 19, 20, 21, 22, 23}}},
    {SimdShuffle::kS64x2ReverseBytes,
     {{7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8}}},
    {SimdShuffle::kS64x2Reverse,
     {{8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7}}},
    {SimdShuffle::kS64x2Even,
     {{0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23}}},
    {SimdShuffle::kS64x2Odd,
     {{8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31}}},
    {SimdShuffle::kS32x4ReverseBytes,
     {{3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12}}},
    {SimdShuffle::kS32x4Reverse,
     {{12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3}}},
    {SimdShuffle::kS32x4InterleaveLowHalves,
     {{0, 1, 2, 3, 16, 17, 18, 19, 4, 5, 6, 7, 20, 21, 22, 23}}},
    {SimdShuffle::kS32x4InterleaveHighHalves,
     {{8, 9, 10, 11, 24, 25, 26, 27, 12, 13, 14, 15, 28, 29, 30, 31}}},
    {SimdShuffle::kS32x4InterleaveEven,
     {{0, 1, 2, 3, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27}}},
    {SimdShuffle::kS32x4InterleaveOdd,
     {{4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31}}},
    {SimdShuffle::kS32x4TransposeEven,
     {{0, 1, 2, 3, 16, 17, 18, 19, 8, 9, 10, 11, 24, 25, 26, 27}}},
    {SimdShuffle::kS32x4TransposeOdd,
     {{4, 5, 6, 7, 20, 21, 22, 23, 12, 13, 14, 15, 28, 29, 30, 31}}},
    {SimdShuffle::kS16x8ReverseBytes,
     {{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14}}},
    {SimdShuffle::kS16x8InterleaveLowHalves,
     {{0, 1, 16, 17, 2, 3, 18, 19, 4, 5, 20, 21, 6, 7, 22, 23}}},
    {SimdShuffle::kS16x8InterleaveHighHalves,
     {{8, 9, 24, 25, 10, 11, 26, 27, 12, 13, 28, 29, 14, 15, 30, 31}}},
    {SimdShuffle::kS16x8InterleaveEven,
     {{0, 1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24, 25, 28, 29}}},
    {SimdShuffle::kS16x8InterleaveOdd,
     {{2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31}}},
    {SimdShuffle::kS16x8TransposeEven,
     {{0, 1, 16, 17, 4, 5, 20, 21, 8, 9, 24, 25, 12, 13, 28, 29}}},
    {SimdShuffle::kS16x8TransposeOdd,
     {{2, 3, 18, 19, 6, 7, 22, 23, 10, 11, 26, 27, 14, 15, 30, 31}}},
    {SimdShuffle::kS8x16InterleaveLowHalves,
     {{0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23}}},
    {SimdShuffle::kS8x16InterleaveHighHalves,
     {{8, 24, 9, 25, 10, 26, 11, 27, 12, 28, 13, 29, 14, 30, 15, 31}}},
    {SimdShuffle::kS8x16InterleaveEven,
     {{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}}},
    {SimdShuffle::kS8x16InterleaveOdd,
     {{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31}}},
    {SimdShuffle::kS8x16TransposeEven,
     {{0, 16, 2, 18, 4, 20, 6, 22, 8, 24, 10, 26, 12, 28, 14, 30}}},
    {SimdShuffle::kS8x16TransposeOdd,
     {{1, 17, 3, 19, 5, 21, 7, 23, 9, 25, 11, 27, 13, 29, 15, 31}}},
    {SimdShuffle::kS32x2Reverse,
     {{4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11}}},
    {SimdShuffle::kS16x4Reverse,
     {{6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9}}},
    {SimdShuffle::kS16x2Reverse,
     {{2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13}}},
};

TEST_F(SimdShuffleTest, CanonicalMatchers) {
  for (auto& pair : test_shuffles) {
    EXPECT_EQ(pair.first, SimdShuffle::TryMatchCanonical(pair.second));
  }
}

TEST(SimdShufflePackTest, PackShuffle4) {
  uint8_t arr[4]{0b0001, 0b0010, 0b0100, 0b1000};
  EXPECT_EQ(0b00001001, SimdShuffle::PackShuffle4(arr));
}

TEST(SimdShufflePackTest, PackBlend8) {
  uint8_t arr[8]{0, 2, 4, 6, 8, 10, 12, 14};
  EXPECT_EQ(0b11110000, SimdShuffle::PackBlend8(arr));
}

TEST(SimdShufflePackTest, PackBlend4) {
  uint8_t arr[4]{0, 2, 4, 6};
  EXPECT_EQ(0b11110000, SimdShuffle::PackBlend4(arr));
}

TEST(SimdShufflePackTest, Pack4Lanes) {
  uint8_t arr[4]{0x01, 0x08, 0xa0, 0x7c};
  EXPECT_EQ(0x7ca00801, SimdShuffle::Pack4Lanes(arr));
}

TEST(SimdShufflePackTest, Pack16Lanes) {
  uint8_t arr[16]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  uint32_t imms[4]{0};
  SimdShuffle::Pack16Lanes(imms, arr);
  EXPECT_THAT(imms,
              ElementsAre(0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c));
}

#ifdef V8_TARGET_ARCH_X64
TEST_F(SimdShuffleTest, TryMatchVpshufd) {
  uint8_t shuffle32x8[8];
  EXPECT_TRUE(TryMatch32x8Shuffle(
      {{12, 13, 14, 15, 8,  9,  10, 11, 4,  5,  6,  7,  0,  1,  2,  3,
        28, 29, 30, 31, 24, 25, 26, 27, 20, 21, 22, 23, 16, 17, 18, 19}},
      shuffle32x8));

  EXPECT_EQ(shuffle32x8[0], 3);
  EXPECT_EQ(shuffle32x8[1], 2);
  EXPECT_EQ(shuffle32x8[2], 1);
  EXPECT_EQ(shuffle32x8[3], 0);
  EXPECT_EQ(shuffle32x8[4], 7);
  EXPECT_EQ(shuffle32x8[5], 6);
  EXPECT_EQ(shuffle32x8[6], 5);
  EXPECT_EQ(shuffle32x8[7], 4);

  uint8_t control;
  EXPECT_TRUE(TryMatchVpshufd(shuffle32x8, &control));
  EXPECT_EQ(control, 0b00'01'10'11);
}

TEST_F(SimdShuffleTest, TryMatchShufps256) {
  uint8_t shuffle32x8[8];
  EXPECT_TRUE(TryMatch32x8Shuffle(
      {{12, 13, 14, 15, 8,  9,  10, 11, 36, 37, 38, 39, 32, 33, 34, 35,
        28, 29, 30, 31, 24, 25, 26, 27, 52, 53, 54, 55, 48, 49, 50, 51}},
      shuffle32x8));
  EXPECT_EQ(shuffle32x8[0], 3);
  EXPECT_EQ(shuffle32x8[1], 2);
  EXPECT_EQ(shuffle32x8[2], 9);
  EXPECT_EQ(shuffle32x8[3], 8);
  EXPECT_EQ(shuffle32x8[4], 7);
  EXPECT_EQ(shuffle32x8[5], 6);
  EXPECT_EQ(shuffle32x8[6], 13);
  EXPECT_EQ(shuffle32x8[7], 12);

  uint8_t control;
  EXPECT_TRUE(TryMatchShufps256(shuffle32x8, &control));
  EXPECT_EQ(control, 0b00'01'10'11);
}

#endif  // V8_TARGET_ARCH_X64

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```