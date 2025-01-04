Response:
The user is asking for an analysis of the provided C++ source code file `vector_math_test.cc`. The analysis should cover:

1. **Functionality:** What does this code do?
2. **Relationship to web technologies (JavaScript, HTML, CSS):** Is there any connection to how these technologies work?
3. **Logical Reasoning (with examples):** If the code performs calculations, can we illustrate them with hypothetical inputs and outputs?
4. **Common Usage Errors:** What mistakes might developers make when using the code this file tests?

Let's break down the code section by section to understand its purpose.

**Overall Structure:**

The file is a unit test for a library called `vector_math`. It uses the Google Test framework. The tests cover various mathematical operations on vectors (arrays of numbers).

**Key Components:**

* **Headers:** Includes standard C++ libraries (`cmath`, `limits`, `numeric`, `random`), base libraries from Chromium (`base/memory/raw_ptr`, `base/ranges/algorithm`), build configuration, and testing headers (`gtest`). Crucially, it includes the header for the code being tested: `vector_math.h`.
* **Namespaces:** The code resides within `blink::vector_math`.
* **Helper Structs and Constants:**  `MemoryLayout` describes how vectors are stored in memory (alignment and stride). Constants like `kMaxByteAlignment`, `kMaxStride`, `kVectorSizesInBytes` define test parameters.
* **`Equal` Function:** A helper function to compare floating-point numbers, treating NaNs as equal.
* **`TestVector` Template Class:**  A core part of the testing framework. It represents a vector in memory, handling alignment and stride. It provides iterators and comparison operators.
* **`GetPrimaryVectors` and `GetSecondaryVectors` Templates:** Functions to generate test vectors with different memory layouts and sizes. This ensures the `vector_math` functions work correctly under various memory conditions.
* **`VectorMathTest` Class:** The main test fixture. It sets up test data (source and destination buffers) and defines constants for array sizes and indices.
* **`SetUpTestSuite`:**  Initializes the source buffers with random numbers and special values (infinity, NaN) to cover different scenarios.
* **`TEST_F` Macros:**  Define individual test cases, each testing a specific function from the `vector_math` library (e.g., `Conv`, `Vadd`, `Vsub`, `Vmul`, etc.).

**Functionality Breakdown of Individual Tests:**

* **`Conv`:** Tests convolution. It compares the output of the `Conv` function with a manually calculated expected result.
* **`Vadd`:** Tests vector addition.
* **`Vsub`:** Tests vector subtraction.
* **`Vclip`:** Tests clipping values within a range.
* **`Vmaxmgv`:** Tests finding the maximum magnitude within a vector.
* **`Vmul`:** Tests element-wise vector multiplication.
* **`Vsma`:** Tests fused multiply-add with a scalar (destination = destination + scale * source).
* **`Vsmul`:** Tests scalar multiplication of a vector.
* **`Vsadd`:** Tests scalar addition to a vector.
* **`Vsvesq`:** Tests the sum of squares of vector elements.
* **`Zvmul`:** Tests complex number multiplication.

**Connecting to Web Technologies:**

The `vector_math` library, as implied by its location in the Blink renderer, is likely used for audio processing within the web browser.

* **JavaScript:**  JavaScript's Web Audio API allows developers to manipulate audio in the browser. The underlying implementation of the Web Audio API in Blink likely uses optimized math functions like those tested here for tasks such as:
    * **Audio Effects:** Applying effects like reverb, delay, or filters often involves convolution and other vector operations.
    * **Spatialization:**  Positioning audio sources in 3D space requires complex calculations involving vector math.
    * **Analysis:**  Analyzing audio data (e.g., for frequency content) uses mathematical transformations.
* **HTML:** While HTML doesn't directly interact with this low-level math library, it provides the `<audio>` element and the overall structure for web pages that utilize audio.
* **CSS:** CSS doesn't have a direct relationship with this code.

**Logical Reasoning Examples:**

Let's take the `Vadd` test as an example:

**Hypothetical Input:**

* `source1`: A `TestVector` containing `{1.0f, 2.0f, 3.0f}` with a stride of 1.
* `source2`: A `TestVector` containing `{4.0f, 5.0f, 6.0f}` with a stride of 1.

**Expected Output:**

* `expected_dest`: A `TestVector` containing `{5.0f, 7.0f, 9.0f}`.
* The `Vadd` function should modify the destination vector to contain these values.

**Example with Strides:**

If `source1` contained the same data but with a stride of 2, the underlying memory might look like `{1.0f, X, 2.0f, X, 3.0f}` (where 'X' is some other value). The `Vadd` operation would still treat it as the vector `{1.0f, 2.0f, 3.0f}`.

**Common Usage Errors:**

* **Incorrect Stride:** Providing an incorrect stride to the `vector_math` functions could lead to accessing the wrong memory locations and producing incorrect results or even crashes.
    * **Example:** If `source1` has a stride of 2, but you tell `Vadd` the stride is 1, it will read consecutive memory locations instead of skipping elements.
* **Mismatched Sizes:**  If the source and destination vectors have different sizes, the functions might read or write out of bounds. However, the tests here generally ensure the sizes match.
* **Alignment Issues (though less likely for direct users of these functions):** The tests specifically target different memory alignments. If the underlying memory buffers are not correctly aligned as required by specific SIMD instructions (like AVX), the functions might crash or perform suboptimally. The `TestVector` class helps abstract away some of this complexity for the direct user of the `vector_math` functions, but it's something the developers of the `vector_math` library need to be very careful about.
* **NaN Handling:**  Some functions might have specific requirements or behaviors when dealing with NaN (Not a Number) values. The tests explicitly cover scenarios with NaNs. A user might incorrectly assume a function handles NaNs in a specific way.
* **Overflow/Underflow:** While less of a direct usage error, calculations can result in overflow (values exceeding the maximum representable) or underflow (values becoming very close to zero). The `Zvmul` test specifically checks for overflow behavior.

In summary, this file thoroughly tests the low-level vector math functions used by the Blink rendering engine, particularly for audio processing. It verifies correctness under various memory layouts and with different input values, including edge cases like NaNs and infinities. Understanding this code helps to appreciate the performance optimizations and robustness built into web browser audio capabilities.

## 功能概述

`blink/renderer/platform/audio/vector_math_test.cc` 文件是 Chromium Blink 引擎中 **platform/audio** 目录下，专门用于测试 **vector_math.h** 中定义的向量数学运算功能的单元测试文件。

其主要功能是：

1. **验证 `vector_math.h` 中实现的各种向量数学运算函数的正确性。**  这些函数通常针对音频处理的需求进行了优化，可能使用了 SIMD (Single Instruction, Multiple Data) 等技术来提升性能。
2. **测试不同内存布局下的向量运算。**  代码中定义了 `MemoryLayout` 结构体，并生成了具有不同字节对齐和步长的测试向量，以确保向量运算函数在各种内存条件下都能正常工作。
3. **覆盖各种边界情况。**  测试用例中包含了对 NaN (Not a Number) 和 Infinity 等特殊浮点数的处理，以及不同向量大小的测试。

简而言之，这个文件是用来确保 Blink 引擎中用于音频处理的向量数学运算库能够 **正确、高效** 地工作。

## 与 JavaScript, HTML, CSS 的关系

虽然这个 C++ 文件本身不直接包含 JavaScript、HTML 或 CSS 代码，但它所测试的 **向量数学运算库** 是 Web Audio API 的底层实现基础之一。

**关系举例：**

* **JavaScript (Web Audio API):** 当 JavaScript 代码使用 Web Audio API 进行音频处理时，例如：
    * **创建滤波器 (BiquadFilterNode):**  滤波器的系数计算和音频数据的处理会用到向量乘法、加法等运算。`vector_math` 中 `Conv` (卷积) 函数的测试就与滤波器的实现密切相关。
    * **实现混响 (ConvolverNode):** 混响效果的实现通常依赖于音频信号与冲击响应的卷积运算，这正是 `Conv` 函数所测试的功能。
    * **进行音频分析 (AnalyserNode):**  音频分析可能涉及到对音频数据进行傅里叶变换等复杂运算，虽然这个文件没有直接测试傅里叶变换，但其基础的向量运算是构建这些高级算法的基石。
    * **控制音频增益 (GainNode):**  调整音频增益涉及到将音频数据乘以一个标量，`vector_math` 中的 `Vsmul` (向量标量乘法) 函数就直接对应这个操作。
    * **混合多个音频流 (ChannelMergerNode, ChannelSplitterNode):**  这些操作可能需要进行向量的加法和赋值。

* **HTML:**  HTML 的 `<audio>` 标签用于在网页中嵌入音频内容。当 JavaScript 通过 Web Audio API 处理 `<audio>` 标签加载的音频数据时，底层的 `vector_math` 库就在发挥作用。

* **CSS:**  CSS 与这个文件关系不大，它主要负责网页的样式和布局，不涉及底层的音频数据处理。

**举例说明 (基于 `Conv` 测试):**

**假设输入:**

* **JavaScript (Web Audio API):**  一个音频缓冲区 `audioBuffer` 代表一段音频信号。
* **JavaScript (Web Audio API):**  一个表示滤波器冲击响应的 `AudioBuffer` 或一个自定义的滤波器核。

**逻辑推理:**

1. **Blink 引擎 (C++):** 当 Web Audio API 创建一个 `ConvolverNode` 并设置冲击响应时，Blink 引擎会将冲击响应数据和音频数据传递给 `vector_math` 中的 `Conv` 函数进行卷积运算。
2. **`vector_math_test.cc` 中的 `Conv` 测试:** 该测试模拟了这个过程：
    * `source` (在测试中): 模拟输入的音频数据。
    * `reversed_filter` (在测试中): 模拟滤波器的冲击响应 (需要反转)。
    * `Conv` 函数 (在测试中): 执行卷积运算。
    * `expected_dest` (在测试中): 手动计算的期望输出，用于对比 `Conv` 函数的实际输出。

**输出:**

* **Blink 引擎 (C++):** `Conv` 函数计算出的卷积结果作为处理后的音频数据。
* **JavaScript (Web Audio API):**  `ConvolverNode` 的输出是经过滤波后的音频信号，用户可以通过 Web Audio API 的其他节点进一步处理或播放。

## 逻辑推理 (假设输入与输出)

我们以 `Vadd` (向量加法) 测试为例进行说明：

**假设输入:**

* **`source1` (TestVector):**  包含浮点数 `[1.0f, 2.5f, -3.0f]`，步长为 1。
* **`source2` (TestVector):**  包含浮点数 `[0.5f, -1.0f, 4.0f]`，步长为 1。

**`Vadd` 函数的逻辑:** 将 `source1` 和 `source2` 中对应位置的元素相加，结果写入到目标向量。

**预期输出 (`expected_dest`):**

* 包含浮点数 `[1.0f + 0.5f, 2.5f + (-1.0f), -3.0f + 4.0f]`，即 `[1.5f, 1.5f, 1.0f]`。

**`Vadd` 测试会验证实际输出是否与预期输出一致。**

## 用户或编程常见的使用错误

尽管用户通常不会直接调用 `vector_math.h` 中的函数，但理解其背后的原理有助于避免 Web Audio API 的使用错误。

**常见错误举例：**

1. **假设 Web Audio API 的某些操作是同步的，但实际上它们可能是异步的或需要一定的处理时间。**  例如，错误地假设 `ConvolverNode` 在设置冲击响应后立即完成所有计算。
2. **不理解 Web Audio API 中音频数据的格式 (例如，采样率、声道数)。** 这可能导致数据传递给底层 `vector_math` 函数时出现错误，例如步长设置不正确。
3. **在高性能要求的音频处理场景中，过度使用计算密集型的操作，导致性能瓶颈。** 理解 `vector_math` 的存在是为了优化性能，因此应该尽量利用 Web Audio API 提供的节点，而不是自己用 JavaScript 实现复杂的音频处理逻辑。
4. **错误地处理 NaN 和 Infinity 值。**  音频数据中可能出现这些特殊值，如果不进行适当的检查和处理，可能会导致意想不到的结果或程序崩溃。`vector_math_test.cc` 中对这些值的测试表明了 Blink 引擎在底层对这些情况的考虑。

**针对 `vector_math` 函数本身 (开发者可能遇到的错误):**

1. **步长 (Stride) 设置错误:**  如果提供的步长与实际向量在内存中的布局不符，会导致读取或写入错误的内存位置，产生错误的结果甚至崩溃。例如，一个连续存储的数组，步长应该设置为 1，如果错误地设置为其他值，就会跳过一些元素。
2. **内存对齐问题:**  某些 SIMD 指令对内存对齐有要求。如果传递给 `vector_math` 函数的指针未按要求对齐，可能会导致性能下降或程序崩溃。`vector_math_test.cc` 中对不同内存布局的测试正是为了避免这类问题。
3. **缓冲区溢出:**  如果目标缓冲区的空间不足以容纳计算结果，可能会导致数据溢出到其他内存区域，造成程序错误。
4. **不正确的参数传递:**  例如，传递了错误的向量大小、滤波器大小等参数，会导致计算结果错误。

总而言之，`blink/renderer/platform/audio/vector_math_test.cc` 通过细致的测试，确保了 Blink 引擎在处理音频数据时，底层的向量数学运算既准确又高效，这直接关系到 Web Audio API 的稳定性和性能，最终影响用户在网页上体验到的音频效果。

Prompt: 
```
这是目录为blink/renderer/platform/audio/vector_math_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/audio/vector_math.h"

#include <cmath>
#include <limits>
#include <numeric>
#include <random>

#include "base/memory/raw_ptr.h"
#include "base/ranges/algorithm.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink::vector_math {
namespace {

struct MemoryLayout {
  size_t byte_alignment;
  size_t stride;
};

// This is the minimum aligned needed by AVX on x86 family architectures.
constexpr size_t kMaxBitAlignment = 256u;
constexpr size_t kMaxByteAlignment = kMaxBitAlignment / 8u;

constexpr size_t kMaxStride = 2u;

constexpr MemoryLayout kMemoryLayouts[] = {
    {kMaxByteAlignment / 4u, 1u},
    {kMaxByteAlignment / 2u, 1u},
    {kMaxByteAlignment / 2u + kMaxByteAlignment / 4u, 1u},
    {kMaxByteAlignment, 1u},
    {0u, kMaxStride}};
constexpr size_t kMemoryLayoutCount =
    sizeof(kMemoryLayouts) / sizeof(*kMemoryLayouts);

// This is the minimum vector size in bytes needed for MSA instructions on
// MIPS.
constexpr size_t kMaxVectorSizeInBytes = 1024u;
constexpr size_t kVectorSizesInBytes[] = {
    kMaxVectorSizeInBytes,
    // This vector size in bytes is chosen so that the following optimization
    // paths can be tested on x86 family architectures using different memory
    // layouts:
    //  * AVX + SSE + scalar
    //  * scalar + SSE + AVX
    //  * SSE + AVX + scalar
    //  * scalar + AVX + SSE
    // On other architectures, this vector size in bytes results in either
    // optimization + scalar path or scalar path to be tested.
    kMaxByteAlignment + kMaxByteAlignment / 2u + kMaxByteAlignment / 4u};
constexpr size_t kVectorSizeCount =
    sizeof(kVectorSizesInBytes) / sizeof(*kVectorSizesInBytes);

// Compare two floats and consider all NaNs to be equal.
bool Equal(float a, float b) {
  if (std::isnan(a)) {
    return std::isnan(b);
  }
  return a == b;
}

// This represents a real source or destination vector which is aligned, can be
// non-contiguous and can be used as a source or destination vector for
// blink::vector_math functions.
template <typename T>
class TestVector {
  DISALLOW_NEW();

  class Iterator {
    STACK_ALLOCATED();

   public:
    // These types are used by std::iterator_traits used by base::ranges::equal
    // used by TestVector::operator==.
    using difference_type = ptrdiff_t;
    using iterator_category = std::bidirectional_iterator_tag;
    using pointer = T*;
    using reference = T&;
    using value_type = T;

    constexpr Iterator() = default;

    Iterator(T* p, int stride) : p_(p), stride_(stride) {}

    Iterator& operator++() {
      p_ += stride_;
      return *this;
    }
    Iterator operator++(int) {
      Iterator iter = *this;
      ++(*this);
      return iter;
    }
    Iterator& operator--() {
      p_ -= stride_;
      return *this;
    }
    Iterator operator--(int) {
      Iterator iter = *this;
      --(*this);
      return iter;
    }
    bool operator==(const Iterator& other) const { return p_ == other.p_; }
    bool operator!=(const Iterator& other) const { return !(*this == other); }
    T& operator*() const { return *p_; }

   private:
    T* p_ = nullptr;
    size_t stride_ = 0;
  };

 public:
  using ReverseIterator = std::reverse_iterator<Iterator>;

  // These types are used internally by Google Test.
  using const_iterator = Iterator;
  using iterator = Iterator;

  TestVector() = default;
  TestVector(T* base, const MemoryLayout* memory_layout, size_t size)
      : p_(GetAligned(base, memory_layout->byte_alignment)),
        memory_layout_(memory_layout),
        size_(size) {}
  TestVector(T* base, const TestVector<const T>& primary_vector)
      : TestVector(base,
                   primary_vector.memory_layout(),
                   primary_vector.size()) {}

  Iterator begin() const { return Iterator(p_.get(), stride()); }
  Iterator end() const { return Iterator(p_ + size() * stride(), stride()); }
  ReverseIterator rbegin() const { return ReverseIterator(end()); }
  ReverseIterator rend() const { return ReverseIterator(begin()); }
  const MemoryLayout* memory_layout() const { return memory_layout_; }
  T* p() const { return p_; }
  size_t size() const { return size_; }
  int stride() const { return static_cast<int>(memory_layout()->stride); }

  bool operator==(const TestVector& other) const {
    return base::ranges::equal(*this, other, Equal);
  }
  T& operator[](size_t i) const { return p_[i * stride()]; }

 private:
  static T* GetAligned(T* base, size_t byte_alignment) {
    size_t base_byte_alignment = GetByteAlignment(base);
    size_t byte_offset =
        (byte_alignment - base_byte_alignment + kMaxByteAlignment) %
        kMaxByteAlignment;
    T* p = base + byte_offset / sizeof(T);
    size_t p_byte_alignment = GetByteAlignment(p);
    CHECK_EQ(byte_alignment % kMaxByteAlignment, p_byte_alignment);
    return p;
  }
  static size_t GetByteAlignment(T* p) {
    return reinterpret_cast<size_t>(p) % kMaxByteAlignment;
  }

  raw_ptr<T, AllowPtrArithmetic> p_;
  raw_ptr<const MemoryLayout> memory_layout_;
  size_t size_;
};

// Get primary input vectors with difference memory layout and size
// combinations.
template <typename T>
Vector<TestVector<const T>> GetPrimaryVectors(const T* base) {
  Vector<TestVector<const T>> vectors(kVectorSizeCount * kMemoryLayoutCount);
  for (auto& vector : vectors) {
    ptrdiff_t i = &vector - &vectors[0];
    ptrdiff_t memory_layout_index = i % kMemoryLayoutCount;
    ptrdiff_t size_index = i / kMemoryLayoutCount;
    vector = TestVector<const T>(base, &kMemoryLayouts[memory_layout_index],
                                 kVectorSizesInBytes[size_index] / sizeof(T));
  }
  return vectors;
}

// Get secondary input or output vectors. As the size of a secondary vector
// must always be the same as the size of the primary input vector, there are
// only  two interesting secondary vectors:
//  - A vector with the same memory layout as the primary input vector has and
//    which therefore is aligned whenever the primary input vector is aligned.
//  - A vector with a different memory layout than the primary input vector has
//    and which therefore is not aligned when the primary input vector is
//    aligned.
template <typename T>
Vector<TestVector<T>> GetSecondaryVectors(
    T* base,
    const MemoryLayout* primary_memory_layout,
    size_t size) {
  Vector<TestVector<T>> vectors(2u);
  const MemoryLayout* other_memory_layout =
      &kMemoryLayouts[primary_memory_layout == &kMemoryLayouts[0]];
  CHECK_NE(primary_memory_layout, other_memory_layout);
  CHECK_NE(primary_memory_layout->byte_alignment,
           other_memory_layout->byte_alignment);
  vectors[0] = TestVector<T>(base, primary_memory_layout, size);
  vectors[1] = TestVector<T>(base, other_memory_layout, size);
  return vectors;
}

template <typename T>
Vector<TestVector<T>> GetSecondaryVectors(
    T* base,
    const TestVector<const float>& primary_vector) {
  return GetSecondaryVectors(base, primary_vector.memory_layout(),
                             primary_vector.size());
}

class VectorMathTest : public testing::Test {
 protected:
  enum {
    kDestinationCount = 4u,
    kFloatArraySize =
        (kMaxStride * kMaxVectorSizeInBytes + kMaxByteAlignment - 1u) /
        sizeof(float),
    kFullyFiniteSource = 4u,
    kFullyFiniteSource2 = 5u,
    kFullyNonNanSource = 6u,
    kSourceCount = 7u
  };

  // Get a destination buffer containing initially uninitialized floats.
  float* GetDestination(size_t i) {
    CHECK_LT(i, static_cast<size_t>(kDestinationCount));
    return destinations_[i];
  }
  // Get a source buffer containing random floats.
  const float* GetSource(size_t i) {
    CHECK_LT(i, static_cast<size_t>(kSourceCount));
    return sources_[i];
  }

  static void SetUpTestSuite() {
    std::minstd_rand generator(3141592653u);
    // Fill in source buffers with finite random floats.
    std::uniform_real_distribution<float> float_distribution(-10.0f, 10.0f);
    std::generate_n(&**sources_, sizeof(sources_) / sizeof(**sources_),
                    [&]() { return float_distribution(generator); });
    // Add INFINITYs and NANs to most source buffers.
    std::uniform_int_distribution<size_t> index_distribution(
        0u, kFloatArraySize / 2u - 1u);
    for (size_t i = 0u; i < kSourceCount; ++i) {
      if (i == kFullyFiniteSource || i == kFullyFiniteSource2) {
        continue;
      }
      sources_[i][index_distribution(generator)] = INFINITY;
      sources_[i][index_distribution(generator)] = -INFINITY;
      if (i != kFullyNonNanSource) {
        sources_[i][index_distribution(generator)] = NAN;
      }
    }
  }

 private:
  static float destinations_[kDestinationCount][kFloatArraySize];
  static float sources_[kSourceCount][kFloatArraySize];
};

float VectorMathTest::destinations_[kDestinationCount][kFloatArraySize];
float VectorMathTest::sources_[kSourceCount][kFloatArraySize];

TEST_F(VectorMathTest, Conv) {
  for (const auto& source : GetPrimaryVectors(GetSource(kFullyFiniteSource))) {
    if (source.stride() != 1) {
      continue;
    }
    for (size_t filter_size : {3u, 32u, 64u, 128u}) {
      // The maximum number of frames which could be processed here is
      // |source.size() - filter_size + 1|. However, in order to test
      // optimization paths, |frames_to_process| should be optimal (divisible
      // by a power of 2) whenever |filter_size| is optimal. Therefore, let's
      // process only |source.size() - filter_size| frames here.
      if (filter_size >= source.size()) {
        break;
      }
      uint32_t frames_to_process = source.size() - filter_size;
      // The stride of a convolution filter must be -1. Let's first create
      // a reversed filter whose stride is 1.
      TestVector<const float> reversed_filter(
          GetSource(kFullyFiniteSource2), source.memory_layout(), filter_size);
      // The filter begins from the reverse beginning of the reversed filter
      // and grows downwards.
      const float* filter_p = &*reversed_filter.rbegin();
      TestVector<float> expected_dest(
          GetDestination(0u), source.memory_layout(), frames_to_process);
      for (size_t i = 0u; i < frames_to_process; ++i) {
        expected_dest[i] = 0u;
        for (size_t j = 0u; j < filter_size; ++j) {
          expected_dest[i] += source[i + j] * *(filter_p - j);
        }
      }
      for (auto& dest : GetSecondaryVectors(
               GetDestination(1u), source.memory_layout(), frames_to_process)) {
        AudioFloatArray prepared_filter;
        PrepareFilterForConv(filter_p, -1, filter_size, &prepared_filter);
        Conv(source.p(), 1, filter_p, -1, dest.p(), 1, frames_to_process,
             filter_size, &prepared_filter);
        for (size_t i = 0u; i < frames_to_process; ++i) {
          EXPECT_NEAR(expected_dest[i], dest[i],
                      1e-3 * std::abs(expected_dest[i]));
        }
      }
    }
  }
}

TEST_F(VectorMathTest, Vadd) {
  for (const auto& source1 : GetPrimaryVectors(GetSource(0u))) {
    for (const auto& source2 : GetSecondaryVectors(GetSource(1u), source1)) {
      TestVector<float> expected_dest(GetDestination(0u), source1);
      for (size_t i = 0u; i < source1.size(); ++i) {
        expected_dest[i] = source1[i] + source2[i];
      }
      for (auto& dest : GetSecondaryVectors(GetDestination(1u), source1)) {
        Vadd(source1.p(), source1.stride(), source2.p(), source2.stride(),
             dest.p(), dest.stride(), source1.size());
        EXPECT_EQ(expected_dest, dest);
      }
    }
  }
}

TEST_F(VectorMathTest, Vsub) {
  for (const auto& source1 : GetPrimaryVectors(GetSource(0u))) {
    for (const auto& source2 : GetSecondaryVectors(GetSource(1u), source1)) {
      TestVector<float> expected_dest(GetDestination(0u), source1);
      for (size_t i = 0u; i < source1.size(); ++i) {
        expected_dest[i] = source1[i] - source2[i];
      }
      for (auto& dest : GetSecondaryVectors(GetDestination(1u), source1)) {
        Vsub(source1.p(), source1.stride(), source2.p(), source2.stride(),
             dest.p(), dest.stride(), source1.size());
        EXPECT_EQ(expected_dest, dest);
      }
    }
  }
}

TEST_F(VectorMathTest, Vclip) {
  // Vclip does not accept NaNs thus let's use only sources without NaNs.
  for (const auto& source : GetPrimaryVectors(GetSource(kFullyNonNanSource))) {
    const float* thresholds = GetSource(kFullyFiniteSource);
    const float low_threshold = std::min(thresholds[0], thresholds[1]);
    const float high_threshold = std::max(thresholds[0], thresholds[1]);
    TestVector<float> expected_dest(GetDestination(0u), source);
    for (size_t i = 0u; i < source.size(); ++i) {
      expected_dest[i] = ClampTo(source[i], low_threshold, high_threshold);
    }
    for (auto& dest : GetSecondaryVectors(GetDestination(1u), source)) {
      Vclip(source.p(), source.stride(), &low_threshold, &high_threshold,
            dest.p(), dest.stride(), source.size());
      EXPECT_EQ(expected_dest, dest);
    }
  }
}

TEST_F(VectorMathTest, Vmaxmgv) {
  const auto maxmg = [](float init, float x) {
    return std::max(init, std::abs(x));
  };
  // Vmaxmgv does not accept NaNs thus let's use only sources without NaNs.
  for (const float* source_base :
       {GetSource(kFullyFiniteSource), GetSource(kFullyNonNanSource)}) {
    for (const auto& source : GetPrimaryVectors(source_base)) {
      const float expected_max =
          std::accumulate(source.begin(), source.end(), 0.0f, maxmg);
      float max;
      Vmaxmgv(source.p(), source.stride(), &max, source.size());
      EXPECT_EQ(expected_max, max) << testing::PrintToString(source);
    }
  }
}

TEST_F(VectorMathTest, Vmul) {
  for (const auto& source1 : GetPrimaryVectors(GetSource(0u))) {
    for (const auto& source2 : GetSecondaryVectors(GetSource(1u), source1)) {
      TestVector<float> expected_dest(GetDestination(0u), source1);
      for (size_t i = 0u; i < source1.size(); ++i) {
        expected_dest[i] = source1[i] * source2[i];
      }
      for (auto& dest : GetSecondaryVectors(GetDestination(1u), source1)) {
        Vmul(source1.p(), source1.stride(), source2.p(), source2.stride(),
             dest.p(), dest.stride(), source1.size());
        EXPECT_EQ(expected_dest, dest);
      }
    }
  }
}

TEST_F(VectorMathTest, Vsma) {
  for (const auto& source : GetPrimaryVectors(GetSource(0u))) {
    const float scale = *GetSource(1u);
    const TestVector<const float> dest_source(GetSource(2u), source);
    TestVector<float> expected_dest(GetDestination(0u), source);
    for (size_t i = 0u; i < source.size(); ++i) {
      expected_dest[i] = dest_source[i] + scale * source[i];
    }
    for (auto& dest : GetSecondaryVectors(GetDestination(1u), source)) {
      base::ranges::copy(dest_source, dest.begin());
      Vsma(source.p(), source.stride(), &scale, dest.p(), dest.stride(),
           source.size());
      // Different optimizations may use different precisions for intermediate
      // results which may result in different rounding errors thus let's
      // expect only mostly equal floats.
      for (size_t i = 0u; i < source.size(); ++i) {
        if (std::isfinite(expected_dest[i])) {
#if BUILDFLAG(IS_MAC)
          // On Mac, OS provided vectorized functions are used which may result
          // in bigger rounding errors than functions used on other OSes.
          EXPECT_NEAR(expected_dest[i], dest[i],
                      1e-5 * std::abs(expected_dest[i]));
#else
          EXPECT_FLOAT_EQ(expected_dest[i], dest[i]);
#endif
        } else {
          EXPECT_PRED2(Equal, expected_dest[i], dest[i]);
        }
      }
    }
  }
}

TEST_F(VectorMathTest, Vsmul) {
  for (const auto& source : GetPrimaryVectors(GetSource(0u))) {
    const float scale = *GetSource(1u);
    TestVector<float> expected_dest(GetDestination(0u), source);
    for (size_t i = 0u; i < source.size(); ++i) {
      expected_dest[i] = scale * source[i];
    }
    for (auto& dest : GetSecondaryVectors(GetDestination(1u), source)) {
      Vsmul(source.p(), source.stride(), &scale, dest.p(), dest.stride(),
            source.size());
      EXPECT_EQ(expected_dest, dest);
    }
  }
}

TEST_F(VectorMathTest, Vsadd) {
  for (const auto& source : GetPrimaryVectors(GetSource(0u))) {
    const float addend = *GetSource(1u);
    TestVector<float> expected_dest(GetDestination(0u), source);
    for (size_t i = 0u; i < source.size(); ++i) {
      expected_dest[i] = addend + source[i];
    }
    for (auto& dest : GetSecondaryVectors(GetDestination(1u), source)) {
      Vsadd(source.p(), source.stride(), &addend, dest.p(), dest.stride(),
            source.size());
      EXPECT_EQ(expected_dest, dest);
    }
  }
}

TEST_F(VectorMathTest, Vsvesq) {
  const auto sqsum = [](float init, float x) { return init + x * x; };
  for (const float* source_base :
       {GetSource(0u), GetSource(kFullyFiniteSource)}) {
    for (const auto& source : GetPrimaryVectors(source_base)) {
      const float expected_sum =
          std::accumulate(source.begin(), source.end(), 0.0f, sqsum);
      float sum;
      Vsvesq(source.p(), source.stride(), &sum, source.size());
      if (std::isfinite(expected_sum)) {
        // Optimized paths in Vsvesq use parallel partial sums which may result
        // in different rounding errors than the non-partial sum algorithm used
        // here and in non-optimized paths in Vsvesq.
        EXPECT_FLOAT_EQ(expected_sum, sum);
      } else {
        EXPECT_PRED2(Equal, expected_sum, sum);
      }
    }
  }
}

TEST_F(VectorMathTest, Zvmul) {
  constexpr float kMax = std::numeric_limits<float>::max();
  Vector<Vector<float>> sources(4u);
  for (size_t i = 0u; i < sources.size(); ++i) {
    sources[i].resize(kFloatArraySize);
    // Initialize a local source with a randomized test case source.
    std::copy_n(GetSource(i), kFloatArraySize, sources[i].begin());
    // Put +FLT_MAX and -FLT_MAX in the middle of the source. Use a different
    // sequence for each source in order to get 16 different combinations.
    for (size_t j = 0u; j < 16u; ++j) {
      sources[i][kFloatArraySize / 2u + j] = ((j >> i) & 1) ? -kMax : kMax;
    }
  }
  for (const auto& real1 : GetPrimaryVectors(sources[0u].data())) {
    if (real1.stride() != 1) {
      continue;
    }
    const TestVector<const float> imag1(sources[1u].data(), real1);
    const TestVector<const float> real2(sources[2u].data(), real1);
    const TestVector<const float> imag2(sources[3u].data(), real1);
    TestVector<float> expected_dest_real(GetDestination(0u), real1);
    TestVector<float> expected_dest_imag(GetDestination(1u), real1);
    for (size_t i = 0u; i < real1.size(); ++i) {
      expected_dest_real[i] = real1[i] * real2[i] - imag1[i] * imag2[i];
      expected_dest_imag[i] = real1[i] * imag2[i] + imag1[i] * real2[i];
      if (&real1[i] >= &sources[0u][kFloatArraySize / 2u] &&
          &real1[i] < &sources[0u][kFloatArraySize / 2u] + 16u) {
        // FLT_MAX products should have overflowed.
        EXPECT_TRUE(std::isinf(expected_dest_real[i]) ||
                    std::isnan(expected_dest_real[i]));
        EXPECT_TRUE(std::isinf(expected_dest_imag[i]) ||
                    std::isnan(expected_dest_imag[i]));
      }
    }
    for (auto& dest_real : GetSecondaryVectors(GetDestination(2u), real1)) {
      TestVector<float> dest_imag(GetDestination(3u), real1);
      ASSERT_EQ(1, dest_real.stride());
      Zvmul(real1.p(), imag1.p(), real2.p(), imag2.p(), dest_real.p(),
            dest_imag.p(), real1.size());
      // Different optimizations may use different precisions for intermediate
      // results which may result in different rounding errors thus let's
      // expect only mostly equal floats.
#if BUILDFLAG(IS_MAC)
#if defined(ARCH_CPU_ARM64)
      const float threshold = 1.900e-5;
#else
      const float threshold = 1.5e-5;
#endif
#endif
      for (size_t i = 0u; i < real1.size(); ++i) {
        if (std::isfinite(expected_dest_real[i])) {
#if BUILDFLAG(IS_MAC)
          // On Mac, OS provided vectorized functions are used which may result
          // in bigger rounding errors than functions used on other OSes.
          EXPECT_NEAR(expected_dest_real[i], dest_real[i],
                      threshold * std::abs(expected_dest_real[i]));
#else
          EXPECT_FLOAT_EQ(expected_dest_real[i], dest_real[i]);
#endif
        } else {
#if BUILDFLAG(IS_MAC)
          // On Mac, OS provided vectorized functions are used which may result
          // in different NaN handling than functions used on other OSes.
          EXPECT_TRUE(!std::isfinite(dest_real[i]));
#else
          EXPECT_PRED2(Equal, expected_dest_real[i], dest_real[i]);
#endif
        }
        if (std::isfinite(expected_dest_imag[i])) {
#if BUILDFLAG(IS_MAC)
          // On Mac, OS provided vectorized functions are used which may result
          // in bigger rounding errors than functions used on other OSes.
          EXPECT_NEAR(expected_dest_imag[i], dest_imag[i],
                      1e-5 * std::abs(expected_dest_imag[i]));
#else
          EXPECT_FLOAT_EQ(expected_dest_imag[i], dest_imag[i]);
#endif
        } else {
#if BUILDFLAG(IS_MAC)
          // On Mac, OS provided vectorized functions are used which may result
          // in different NaN handling than functions used on other OSes.
          EXPECT_TRUE(!std::isfinite(dest_imag[i]));
#else
          EXPECT_PRED2(Equal, expected_dest_imag[i], dest_imag[i]);
#endif
        }
      }
    }
  }
}

}  // namespace
}  // namespace blink::vector_math

"""

```