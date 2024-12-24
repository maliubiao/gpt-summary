Response: The user wants a summary of the functionality of the C++ source code file `v8/test/unittests/wasm/simd-shuffle-unittest.cc`.

This file appears to be a unit test file for SIMD shuffle operations within the V8 JavaScript engine's WebAssembly implementation. It tests various aspects of how SIMD shuffles are canonicalized and matched against known patterns.

Here's a breakdown of what the code does:

1. **Includes:** It includes necessary headers for SIMD shuffle functionality, unit testing, and Google Mock support.
2. **Namespace:**  It operates within the `v8::internal::wasm` namespace.
3. **`SimdShuffleTest` Class:** This class serves as a test fixture, providing helper functions to access and test private members of the `SimdShuffle` class.
4. **Helper Types:** It defines `Shuffle` and `TestShuffle` types to represent shuffle masks and test cases.
5. **Static Methods for Testing Private Functions:** The `SimdShuffleTest` class includes static methods that directly call private methods in the `SimdShuffle` class, such as `CanonicalizeShuffle`, `TryMatchIdentity`, `TryMatchSplat`, and various `TryMatch` functions for specific shuffle patterns (e.g., 64x2, 32x4, 16x8 shuffles, concat, blend).
6. **Equality Operator for Shuffles:** It defines an `operator==` for comparing `Shuffle` arrays.
7. **Test Cases:** The core of the file consists of various `TEST_F` macros defining individual unit tests. These tests cover:
    - **`CanonicalizeShuffle`:** Tests the canonicalization process for shuffle masks, ensuring they are converted to a standard form, and identifying if a swap operation is needed and if it represents a swizzle.
    - **`TryMatchIdentity`:** Checks if a shuffle mask represents an identity operation.
    - **`TryMatchSplat`:** Verifies if a shuffle mask represents a splat operation, where all lanes are filled with the same value from a source lane.
    - **`TryMatchConcat`:** Tests if a shuffle mask represents a concatenation operation.
    - **`TryMatch32x4Shuffle`, `TryMatch32x8Shuffle`, `TryMatch16x8Shuffle`:**  These tests check if a shuffle mask corresponds to specific lane arrangements for 32-bit and 16-bit lanes.
    - **`TryMatch32x4Reverse`, `TryMatch32x4OneLaneSwizzle`:** Tests for specific 32-bit lane shuffle patterns.
    - **`TryMatchBlend`:** Checks if a shuffle mask represents a blend operation.
    - **`PairwiseReduce`, `UpperToLowerReduce`:** Tests for specific reduction patterns.
    - **`Shuffle64x2`:** Tests matching for 64x2 shuffle patterns.
    - **`CanonicalMatchers`:**  Iterates through a map of known canonical shuffles and verifies the `TryMatchCanonical` function correctly identifies them.
8. **Packing Tests (`SimdShufflePackTest`):**  This separate test suite focuses on packing shuffle and blend masks into integer values.
9. **Architecture-Specific Tests (`V8_TARGET_ARCH_X64`):**  Includes tests specifically for x64 architecture, checking for patterns like `vpshufd` and `shufps256` instructions.
10. **`test_shuffles` Map:**  A map holding known canonical shuffle patterns and their corresponding byte arrangements.

**In essence, the primary function of this file is to thoroughly test the `SimdShuffle` class's ability to:**

- Canonicalize shuffle masks.
- Recognize common and optimized shuffle patterns.
- Correctly identify these patterns for code generation and optimization purposes within the V8 WebAssembly implementation.
这个C++源代码文件 `v8/test/unittests/wasm/simd-shuffle-unittest.cc` 是一个**单元测试文件**，专门用于测试 V8 JavaScript 引擎中 WebAssembly (Wasm) 部分的 **SIMD (Single Instruction, Multiple Data) shuffle 操作**相关的功能。

具体来说，它的主要功能是：

1. **测试 `SimdShuffle` 类的各种静态方法：**  该文件创建了一个名为 `SimdShuffleTest` 的测试 fixture 类，它允许访问和测试 `src/wasm/simd-shuffle.h` 中 `SimdShuffle` 类的私有静态方法。这些方法主要用于：
    * **规范化 (Canonicalize) Shuffle 模式：** `CanonicalizeShuffle` 方法用于将一个 shuffle 掩码转换为规范的形式，并判断是否需要交换输入操作数以及是否为 swizzle 操作。
    * **匹配 (Match) 特定 Shuffle 模式：**  一系列 `TryMatch...` 方法用于尝试将给定的 shuffle 掩码与预定义的已知模式进行匹配，例如：
        * `TryMatchIdentity`: 匹配恒等变换。
        * `TryMatchSplat`: 匹配将单个通道的值复制到所有通道。
        * `TryMatchConcat`: 匹配连接两个向量的操作。
        * `TryMatch64x2Shuffle`, `TryMatch32x4Shuffle`, `TryMatch32x8Shuffle`, `TryMatch16x8Shuffle`: 匹配特定通道大小的 shuffle 模式。
        * `TryMatch32x4Reverse`, `TryMatch32x4OneLaneSwizzle`: 匹配特定的 32 位通道 shuffle 模式。
        * `TryMatchBlend`: 匹配 blend 操作。
    * **匹配约简 (Reduce) 操作：** 例如 `TryMatch64x2Reduce`, `TryMatch32x4PairwiseReduce`, `TryMatch32x4UpperToLowerReduce` 等。
    * **匹配规范化的 Shuffle 模式：** `TryMatchCanonical` 方法用于匹配预定义的、已知的规范化 shuffle 模式。
    * **架构特定的匹配 (如 x64)：** 例如 `TryMatchVpshufd`, `TryMatchShufps256` 用于匹配特定的 x64 SIMD 指令。
    * **打包 (Pack) Shuffle 和 Blend 掩码：** `PackShuffle4`, `PackBlend8`, `PackBlend4`, `Pack4Lanes`, `Pack16Lanes` 等函数用于将 shuffle 和 blend 掩码打包成整数值。

2. **提供各种测试用例：** 该文件包含了大量的 `TEST_F` 宏定义的测试用例，针对 `SimdShuffle` 类的不同方法和不同的 shuffle 模式进行测试。这些测试用例涵盖了：
    * **规范化测试：** 测试在不同输入下的 shuffle 掩码规范化结果。
    * **模式匹配测试：** 测试各种预定义的 shuffle 模式是否能被正确匹配。
    * **边界条件测试：**  可能包含一些对边界情况的测试。
    * **架构特定指令的匹配测试：** 在 x64 架构下测试特定 SIMD 指令的匹配。

3. **使用 Google Test 框架：** 该文件使用了 Google Test 框架进行单元测试，包括 `TEST_F`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `ElementsAre` 等断言和匹配器。

**总结来说，`v8/test/unittests/wasm/simd-shuffle-unittest.cc` 确保了 V8 引擎中 Wasm SIMD shuffle 功能的正确性和可靠性，通过测试其识别和处理各种 shuffle 模式的能力，从而保证了 Wasm 代码在执行 SIMD 操作时的效率和准确性。**

Prompt: ```这是目录为v8/test/unittests/wasm/simd-shuffle-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
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

"""
```