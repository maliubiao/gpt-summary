Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/objects/simd.cc`, its relationship to JavaScript, examples, logical reasoning, and potential programming errors. The filename itself, including "simd", strongly suggests it's related to Single Instruction, Multiple Data optimizations.

2. **Initial Scan and Keyword Identification:**  Read through the code, looking for key terms and patterns:
    * `#include`: Standard C++ includes like `<immintrin.h>` and `<arm_neon.h>` are strong indicators of SIMD usage for x86/x64 and ARM architectures, respectively.
    * `namespace v8::internal`: This clearly places the code within the V8 JavaScript engine's internals.
    * `enum class SimdKinds`:  Identifies different SIMD instruction sets (SSE, Neon, AVX2). This is crucial for understanding the conditional logic.
    * `get_vectorization_kind()`: A function to determine the available SIMD capabilities at runtime.
    * `slow_search()` and `fast_search_*()`:  Suggests a performance optimization strategy – a basic implementation and faster SIMD-accelerated versions.
    * `VECTORIZED_LOOP_*`: Macros that likely encapsulate the core SIMD loop logic.
    * `ArrayIndexOfIncludes*`: Functions named like this strongly indicate implementation details for JavaScript's `Array.prototype.indexOf` and `Array.prototype.includes` methods.
    * Type names like `uint32x4_t`, `__m128i`, `double*`: These are SIMD-specific data types.

3. **Focus on Core Functionality:** The `search()` template function is central. It selects either the `fast_search_avx` (if AVX2 is available) or `fast_search_noavx` function. `fast_search_noavx` also handles the case where no SIMD is available using `slow_search`. This establishes the main flow: check for SIMD capability and use the appropriate search implementation.

4. **Analyze SIMD Implementations (`fast_search_*`):**
    * **Common Structure:**  Both `fast_search_noavx` and `fast_search_avx` follow a pattern:
        * Alignment handling: Scalar loop to align the array pointer for efficient SIMD loads.
        * Vectorized loop: Use SIMD intrinsics (`_mm_*` for x86, `v_*` for ARM) to load and compare multiple elements in parallel.
        * Fallback: `slow_search` handles remaining elements.
    * **Architecture-Specific Intrinsics:** Notice the distinct sets of intrinsics for x86 (`__m128i`, `_mm_cmpeq_epi32`) and ARM (`uint32x4_t`, `vceqq_u32`). This highlights the platform-specific nature of SIMD.
    * **`extract_first_nonzero_index_*` (Neon):** This function is a clever way to find the first match within a Neon vector, mimicking the movemask/tzcnt approach on x86.

5. **Connect to JavaScript:** The `ArrayIndexOfIncludes*` functions are the bridge. They are called with `Address` and `uintptr_t` (likely memory pointers and lengths) and return an `Address` representing the index or -1. This strongly suggests they are the low-level implementations for JavaScript's array search methods.

6. **Construct JavaScript Examples:** Based on the identified functionality, create simple JavaScript examples that would trigger these C++ functions. `indexOf` and `includes` are the obvious choices for array searching. Demonstrate cases with primitives (numbers) and objects, aligning with the `ArrayIndexOfIncludesKind` enum.

7. **Infer Logical Reasoning:**
    * **Input/Output:**  Consider the inputs to the `search` function (array, length, start index, search element) and its output (the index or -1). Create concrete examples with different data types and SIMD availability to illustrate the logic.
    * **SIMD Benefit:** Emphasize how SIMD allows processing multiple array elements simultaneously, leading to performance gains for large arrays.

8. **Identify Potential Programming Errors:** Focus on common pitfalls related to the techniques used in the code:
    * **Data Type Mismatch:**  Searching for the wrong type in an array.
    * **NaN Handling:** The special behavior of NaN in comparisons.
    * **Alignment Issues (Implicit):** Although the code handles alignment, a user wouldn't directly encounter this as an error. It's more of an internal optimization consideration. Initially, I might think about buffer overflows, but the code doesn't appear to have obvious vulnerabilities in that regard given the length checks. Focus on the *user-facing* errors.

9. **Structure the Response:** Organize the information logically:
    * Start with a high-level overview of the file's purpose.
    * Detail the key functionalities (SIMD detection, vectorized search, fallback).
    * Explain the relationship to JavaScript.
    * Provide clear JavaScript examples.
    * Illustrate the logical reasoning with input/output scenarios.
    * Discuss common programming errors.
    * If applicable, mention Torque (in this case, it's not a Torque file).

10. **Refine and Elaborate:** Review the generated response for clarity, accuracy, and completeness. Ensure the explanations are easy to understand, especially the SIMD concepts. Add details like the specific SIMD instructions used where appropriate.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive and accurate response to the request. The process involves understanding the problem, identifying key components, connecting the code to its higher-level purpose (JavaScript execution), and providing illustrative examples and explanations.
根据提供的 V8 源代码文件 `v8/src/objects/simd.cc`，我们可以分析出以下功能：

**主要功能： 针对数组的 `indexOf` 和 `includes` 方法进行 SIMD (Single Instruction, Multiple Data) 优化。**

这个文件实现了针对特定数据类型的数组进行快速查找的功能，利用了 CPU 的 SIMD 指令集（例如 SSE3, AVX2, Neon）来并行比较多个数组元素，从而提升 `indexOf` 和 `includes` 等方法的性能。

**具体功能点:**

1. **SIMD 支持检测:**
   - 代码首先通过 `get_vectorization_kind()` 函数检测当前 CPU 支持的 SIMD 指令集（SSE, Neon, AVX2 或 None）。
   - 这决定了后续使用哪种 SIMD 优化策略。

2. **非 SIMD 的线性搜索 (`slow_search`):**
   - 提供了一个基础的、非向量化的线性搜索实现，作为 SIMD 不可用时的回退方案，以及处理数组尾部无法被 SIMD 指令完整处理的部分。

3. **基于 SIMD 的快速搜索 (`fast_search_noavx`, `fast_search_avx`):**
   - 针对不同的 SIMD 指令集（SSE/Neon 和 AVX2）提供了优化的搜索实现。
   - 这些函数会将数组中的多个元素加载到 SIMD 寄存器中，然后使用 SIMD 指令并行地与目标元素进行比较。
   - **对齐优化:** 在 SIMD 搜索前，会进行一个小的标量循环，确保数组指针按 SIMD 指令要求的字节数对齐，以提高性能。
   - **`extract_first_nonzero_index_*` (针对 Neon):**  这个函数用于在 Neon 向量中快速找到第一个匹配元素的索引。它通过位运算技巧模拟了 x86 架构上的 `movemask` 和 `tzcnt` 指令的功能。

4. **`ArrayIndexOfIncludes` 模板函数:**
   - 这是一个模板函数，根据 `ArrayIndexOfIncludesKind` 枚举的值，选择不同的搜索策略。
   - 支持两种类型：
     - `DOUBLE`:  用于在 `FixedDoubleArray` 中搜索双精度浮点数 (double) 或小的整数 (Smi)。
     - `OBJECTORSMI`: 用于在 `FixedArray` 中搜索对象或小的整数 (Smi)。

5. **`ArrayIndexOfIncludesSmiOrObject` 和 `ArrayIndexOfIncludesDouble` 函数:**
   - 这两个函数是 `ArrayIndexOfIncludes` 模板函数的具体实例化，用于处理不同类型的数组查找。

**关于 .tq 结尾:**

如果 `v8/src/objects/simd.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。 Torque 是一种 V8 使用的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。  **但根据你提供的代码内容，这个文件是 `.cc` 结尾的，所以它是标准的 C++ 源代码。**

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/simd.cc` 中实现的功能直接影响 JavaScript 中数组的 `indexOf()` 和 `includes()` 方法的性能，尤其是在处理包含大量数字的数组时。

**JavaScript 示例:**

```javascript
const numbers = new Array(1000).fill(0).map((_, i) => i * 2);
const target = 500;

// 使用 indexOf 查找元素
const index = numbers.indexOf(target);
console.log(index); // 输出: 250

// 使用 includes 检查元素是否存在
const exists = numbers.includes(target);
console.log(exists); // 输出: true
```

在 V8 引擎执行这段 JavaScript 代码时，当调用 `numbers.indexOf(target)` 或 `numbers.includes(target)` 且 `numbers` 是一个存储数字的数组时，V8 内部可能会调用 `ArrayIndexOfIncludesDouble` 函数（如果数组是双精度浮点数）或 `ArrayIndexOfIncludesSmiOrObject` 函数（如果数组是小的整数）。这些 C++ 函数会根据 CPU 的 SIMD 支持情况，选择 `fast_search_avx` 或 `fast_search_noavx` 来加速搜索过程。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `array_start`: 指向一个包含双精度浮点数的 JavaScript 数组的内存起始地址。
- `array_len`: 数组的长度，例如 100。
- `from_index`: 搜索的起始索引，例如 0。
- `search_element`:  要搜索的 JavaScript 数字（可以是 Smi 或 HeapNumber），例如 `50.0`。
- CPU 支持 AVX2 指令集。

**预期输出:**

- 如果数组中存在值为 `50.0` 的元素，则返回其在数组中的索引（一个 `uintptr_t` 值）。
- 如果数组中不存在值为 `50.0` 的元素，则返回表示 `-1` 的 `Smi` 的指针。

**代码逻辑:**

1. `get_vectorization_kind()` 会返回 `SimdKinds::kAVX2`。
2. `ArrayIndexOfIncludesDouble` 函数会被调用。
3. 由于支持 AVX2，`search<double>` 函数会调用 `fast_search_avx`。
4. `fast_search_avx` 会：
   - 可能先进行一个小循环以确保数组地址按 32 字节对齐。
   - 进入主循环，每次加载 8 个双精度浮点数到 `__m256d` 寄存器。
   - 使用 `_mm256_cmp_pd` 指令并行比较这 8 个数与 `search_element` (50.0)。
   - 如果找到匹配项，使用 `_mm256_movemask_pd` 和 `base::bits::CountTrailingZeros32` 找到第一个匹配项的索引并返回。
5. 如果整个 `fast_search_avx` 循环没有找到匹配项，会调用 `slow_search` 处理剩余的少量元素。
6. 如果最终找到匹配项，返回其索引；否则，返回表示 `-1` 的 `Smi` 指针。

**涉及用户常见的编程错误:**

1. **数据类型不匹配:** 用户可能尝试在存储对象的数组中使用针对数字优化的 `indexOf`，或者反之。虽然 JavaScript 会进行类型转换，但这可能不是预期的行为，并且可能无法利用 SIMD 优化。

   ```javascript
   const mixedArray = [1, "2", 3, "4"];
   mixedArray.indexOf(2); // 返回 -1，因为 "2" 是字符串
   ```

2. **比较 `NaN`:**  `NaN` (Not a Number) 与任何值（包括自身）进行比较都返回 `false`。用户可能会期望 `[NaN].indexOf(NaN)` 返回 `0`，但实际上会返回 `-1`。SIMD 优化也遵循这种 IEEE 754 标准。

   ```javascript
   const nanArray = [NaN];
   nanArray.indexOf(NaN); // 返回 -1
   ```

3. **性能预期错误:** 用户可能会误认为所有类型的数组和所有大小的数组都能从 SIMD 优化中获得显著的性能提升。实际上，对于小数组或非数值类型的数组，SIMD 的开销可能超过其带来的收益。

4. **使用不精确的浮点数比较:**  由于浮点数精度问题，直接比较两个浮点数是否相等可能不可靠。SIMD 指令执行的也是精确的位比较，因此用户需要注意浮点数的比较方式。

   ```javascript
   0.1 + 0.2 === 0.3; // 返回 false
   const floatArray = [0.1 + 0.2];
   floatArray.indexOf(0.3); // 很可能返回 -1
   ```

总而言之，`v8/src/objects/simd.cc` 通过利用 SIMD 指令集，显著提升了 V8 引擎在处理数值类型数组时的 `indexOf` 和 `includes` 方法的性能。理解其背后的原理有助于开发者更好地理解 JavaScript 引擎的优化策略，并避免一些常见的编程错误。

Prompt: 
```
这是目录为v8/src/objects/simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/simd.h"

#include "src/base/cpu.h"
#include "src/codegen/cpu-features.h"
#include "src/objects/compressed-slots.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/smi-inl.h"

#ifdef _MSC_VER
// MSVC doesn't define SSE3. However, it does define AVX, and AVX implies SSE3.
#ifdef __AVX__
#ifndef __SSE3__
#define __SSE3__
#endif
#endif
#endif

#ifdef __SSE3__
#include <immintrin.h>
#endif

#ifdef V8_HOST_ARCH_ARM64
// We use Neon only on 64-bit ARM (because on 32-bit, some instructions and some
// types are not available). Note that ARM64 is guaranteed to have Neon.
#define NEON64
#include <arm_neon.h>
#endif

namespace v8 {
namespace internal {

namespace {

enum class SimdKinds { kSSE, kNeon, kAVX2, kNone };

inline SimdKinds get_vectorization_kind() {
#ifdef __SSE3__
#if defined(V8_TARGET_ARCH_IA32) || defined(V8_TARGET_ARCH_X64)
  bool has_avx2 = CpuFeatures::IsSupported(AVX2);
#else
  bool has_avx2 = false;
#endif
  if (has_avx2) {
    return SimdKinds::kAVX2;
  } else {
    // No need for a runtime check since we do not support x86/x64 CPUs without
    // SSE3.
    return SimdKinds::kSSE;
  }
#elif defined(NEON64)
  // No need for a runtime check since all Arm64 CPUs have Neon.
  return SimdKinds::kNeon;
#else
  return SimdKinds::kNone;
#endif
}

// Searches for |search_element| in |array| using a simple non-vectorized linear
// search. This is used as a fall-back when SIMD are not available, and to
// process the end of arrays than SIMD cannot process.
template <typename T>
inline uintptr_t slow_search(T* array, uintptr_t array_len, uintptr_t index,
                             T search_element) {
  for (; index < array_len; index++) {
    if (array[index] == search_element) {
      return index;
    }
  }
  return -1;
}

#ifdef NEON64
// extract_first_nonzero_index returns the first non-zero index in |v|. |v| is a
// Neon vector that can be either 32x4 (the return is then 0, 1, 2 or 3) or 64x2
// (the return is then 0 or 1). This is more or less equivalent to doing a
// movemask followed by a tzcnt on Intel.
//
// The input |v| should be a vector of -1 or 0 (for instance {0, 0},
// {0, -1, 0, -1}, {0, -1, 0, 0}), where -1 represents a match (and 0 a
// non-match), that was obtained by doing a vceqq. This function extract the
// index of the first non-zero item of the vector. To do so, we "and" the vector
// with {4, 3, 2, 1} (each number is "4 - the index of the item it's in"), which
// produces a vector of "indices or 0". Then, we extract the maximum of this
// vector, which is the index of the 1st match. An example:
//
//   v = {-1, 0, 0, -1}
//   mask = {4, 3, 2, 1}
//   v & mask = {4, 0, 0, 1}
//   max(v & mask) = 4
//   index of the first match = 4-max = 4-4 = 0
//

// With MSVC, uint32x4_t and uint64x2_t typedef to a union, where first member
// is uint64_t[2], and not uint32_t[4].
// C++ standard dictates that a union can only be initialized through its first
// member, which forces us to have uint64_t[2] for definition.
#if defined(_MSC_VER) && !defined(__clang__)
#define PACK32x4(w, x, y, z) \
  { ((w) + (uint64_t(x) << 32)), ((y) + (uint64_t(z) << 32)) }
#else
#define PACK32x4(w, x, y, z) \
  { (w), (x), (y), (z) }
#endif  // MSVC workaround

V8_ALLOW_UNUSED inline int extract_first_nonzero_index_uint32x4_t(
    uint32x4_t v) {
  uint32x4_t mask = PACK32x4(4, 3, 2, 1);
  mask = vandq_u32(mask, v);
  return 4 - vmaxvq_u32(mask);
}

inline int extract_first_nonzero_index_uint64x2_t(uint64x2_t v) {
  uint32x4_t mask =
      PACK32x4(2, 0, 1, 0);  // Could also be {2,2,1,1} or {0,2,0,1}
  mask = vandq_u32(mask, vreinterpretq_u32_u64(v));
  return 2 - vmaxvq_u32(mask);
}

inline int32_t reinterpret_vmaxvq_u64(uint64x2_t v) {
  return vmaxvq_u32(vreinterpretq_u32_u64(v));
}
#endif

#define VECTORIZED_LOOP_Neon(type_load, type_eq, set1, cmp, movemask)        \
  {                                                                          \
    constexpr int elems_in_vector = sizeof(type_load) / sizeof(T);           \
    type_load search_element_vec = set1(search_element);                     \
                                                                             \
    for (; index + elems_in_vector <= array_len; index += elems_in_vector) { \
      type_load vector = *reinterpret_cast<type_load*>(&array[index]);       \
      type_eq eq = cmp(vector, search_element_vec);                          \
      if (movemask(eq)) {                                                    \
        return index + extract_first_nonzero_index_##type_eq(eq);            \
      }                                                                      \
    }                                                                        \
  }

#define VECTORIZED_LOOP_x86(type_load, type_eq, set1, cmp, movemask, extract) \
  {                                                                           \
    constexpr int elems_in_vector = sizeof(type_load) / sizeof(T);            \
    type_load search_element_vec = set1(search_element);                      \
                                                                              \
    for (; index + elems_in_vector <= array_len; index += elems_in_vector) {  \
      type_load vector = *reinterpret_cast<type_load*>(&array[index]);        \
      type_eq eq = cmp(vector, search_element_vec);                           \
      int eq_mask = movemask(eq);                                             \
      if (eq_mask) {                                                          \
        return index + extract(eq_mask);                                      \
      }                                                                       \
    }                                                                         \
  }

#ifdef __SSE3__
__m128i _mm_cmpeq_epi64_nosse4_2(__m128i a, __m128i b) {
  __m128i res = _mm_cmpeq_epi32(a, b);
  // For each 64-bit value swap results of lower 32 bits comparison with
  // the results of upper 32 bits comparison.
  __m128i res_swapped = _mm_shuffle_epi32(res, _MM_SHUFFLE(2, 3, 0, 1));
  // Report match only when both upper and lower parts of 64-bit values match.
  return _mm_and_si128(res, res_swapped);
}
#endif  // __SSE3__

// Uses SIMD to vectorize the search loop. This function should only be called
// for large-ish arrays. Note that nothing will break if |array_len| is less
// than vectorization_threshold: things will just be slower than necessary.
template <typename T>
inline uintptr_t fast_search_noavx(T* array, uintptr_t array_len,
                                   uintptr_t index, T search_element) {
  static constexpr bool is_uint32 =
      sizeof(T) == sizeof(uint32_t) && std::is_integral<T>::value;
  static constexpr bool is_uint64 =
      sizeof(T) == sizeof(uint64_t) && std::is_integral<T>::value;
  static constexpr bool is_double =
      sizeof(T) == sizeof(double) && std::is_floating_point<T>::value;

  static_assert(is_uint32 || is_uint64 || is_double);

#if !(defined(__SSE3__) || defined(NEON64))
  // No SIMD available.
  return slow_search(array, array_len, index, search_element);
#endif

#ifdef __SSE3__
  const int target_align = 16;
#elif defined(NEON64)
  const int target_align = 16;
#else
  const int target_align = 4;
  UNREACHABLE();
#endif

  // Scalar loop to reach desired alignment
  for (;
       index < array_len &&
       (reinterpret_cast<std::uintptr_t>(&(array[index])) % target_align) != 0;
       index++) {
    if (array[index] == search_element) {
      return index;
    }
  }

  // Inserting one of the vectorized loop
#ifdef __SSE3__
  if constexpr (is_uint32) {
#define MOVEMASK(x) _mm_movemask_ps(_mm_castsi128_ps(x))
#define EXTRACT(x) base::bits::CountTrailingZeros32(x)
    VECTORIZED_LOOP_x86(__m128i, __m128i, _mm_set1_epi32, _mm_cmpeq_epi32,
                        MOVEMASK, EXTRACT)
#undef MOVEMASK
#undef EXTRACT
  } else if constexpr (is_uint64) {
#define MOVEMASK(x) _mm_movemask_ps(_mm_castsi128_ps(x))
// _mm_cmpeq_epi64_nosse4_2() might produce only the following non-zero
// patterns:
//   0b0011 -> 0 (the first value matches),
//   0b1100 -> 1 (the second value matches),
//   0b1111 -> 0 (both first and second value match).
// Thus it's enough to check only the least significant bit.
#define EXTRACT(x) (((x) & 1) ? 0 : 1)
    VECTORIZED_LOOP_x86(__m128i, __m128i, _mm_set1_epi64x,
                        _mm_cmpeq_epi64_nosse4_2, MOVEMASK, EXTRACT)
#undef MOVEMASK
#undef EXTRACT
  } else if constexpr (is_double) {
#define EXTRACT(x) base::bits::CountTrailingZeros32(x)
    VECTORIZED_LOOP_x86(__m128d, __m128d, _mm_set1_pd, _mm_cmpeq_pd,
                        _mm_movemask_pd, EXTRACT)
#undef EXTRACT
  }
#elif defined(NEON64)
  if constexpr (is_uint32) {
    VECTORIZED_LOOP_Neon(uint32x4_t, uint32x4_t, vdupq_n_u32, vceqq_u32,
                         vmaxvq_u32)
  } else if constexpr (is_uint64) {
    VECTORIZED_LOOP_Neon(uint64x2_t, uint64x2_t, vdupq_n_u64, vceqq_u64,
                         reinterpret_vmaxvq_u64)
  } else if constexpr (is_double) {
    VECTORIZED_LOOP_Neon(float64x2_t, uint64x2_t, vdupq_n_f64, vceqq_f64,
                         reinterpret_vmaxvq_u64)
  }
#else
  UNREACHABLE();
#endif

  // The vectorized loop stops when there are not enough items left in the array
  // to fill a vector register. The slow_search function will take care of
  // iterating through the few remaining items.
  return slow_search(array, array_len, index, search_element);
}

#if defined(_MSC_VER) && defined(__clang__)
// Generating AVX2 code with Clang on Windows without the /arch:AVX2 flag does
// not seem possible at the moment.
#define IS_CLANG_WIN 1
#endif

// Since we don't compile with -mavx or -mavx2 (or /arch:AVX2 on MSVC), Clang
// and MSVC do not define __AVX__ nor __AVX2__. Thus, if __SSE3__ is defined, we
// generate the AVX2 code, and, at runtime, we'll decide to call it or not,
// depending on whether the CPU supports AVX2.
#if defined(__SSE3__) && !defined(_M_IX86) && !defined(IS_CLANG_WIN)
#ifdef _MSC_VER
#define TARGET_AVX2
#else
#define TARGET_AVX2 __attribute__((target("avx2")))
#endif
template <typename T>
TARGET_AVX2 inline uintptr_t fast_search_avx(T* array, uintptr_t array_len,
                                             uintptr_t index,
                                             T search_element) {
  static constexpr bool is_uint32 =
      sizeof(T) == sizeof(uint32_t) && std::is_integral<T>::value;
  static constexpr bool is_uint64 =
      sizeof(T) == sizeof(uint64_t) && std::is_integral<T>::value;
  static constexpr bool is_double =
      sizeof(T) == sizeof(double) && std::is_floating_point<T>::value;

  static_assert(is_uint32 || is_uint64 || is_double);

  const int target_align = 32;
  // Scalar loop to reach desired alignment
  for (;
       index < array_len &&
       (reinterpret_cast<std::uintptr_t>(&(array[index])) % target_align) != 0;
       index++) {
    if (array[index] == search_element) {
      return index;
    }
  }

  // Generating vectorized loop
  if constexpr (is_uint32) {
#define MOVEMASK(x) _mm256_movemask_ps(_mm256_castsi256_ps(x))
#define EXTRACT(x) base::bits::CountTrailingZeros32(x)
    VECTORIZED_LOOP_x86(__m256i, __m256i, _mm256_set1_epi32, _mm256_cmpeq_epi32,
                        MOVEMASK, EXTRACT)
#undef MOVEMASK
#undef EXTRACT
  } else if constexpr (is_uint64) {
#define MOVEMASK(x) _mm256_movemask_pd(_mm256_castsi256_pd(x))
#define EXTRACT(x) base::bits::CountTrailingZeros32(x)
    VECTORIZED_LOOP_x86(__m256i, __m256i, _mm256_set1_epi64x,
                        _mm256_cmpeq_epi64, MOVEMASK, EXTRACT)
#undef MOVEMASK
#undef EXTRACT
  } else if constexpr (is_double) {
#define CMP(a, b) _mm256_cmp_pd(a, b, _CMP_EQ_OQ)
#define EXTRACT(x) base::bits::CountTrailingZeros32(x)
    VECTORIZED_LOOP_x86(__m256d, __m256d, _mm256_set1_pd, CMP,
                        _mm256_movemask_pd, EXTRACT)
#undef CMP
#undef EXTRACT
  }

  // The vectorized loop stops when there are not enough items left in the array
  // to fill a vector register. The slow_search function will take care of
  // iterating through the few remaining items.
  return slow_search(array, array_len, index, search_element);
}

#undef TARGET_AVX2
#elif defined(IS_CLANG_WIN)
template <typename T>
inline uintptr_t fast_search_avx(T* array, uintptr_t array_len, uintptr_t index,
                                 T search_element) {
  // Falling back to SSE version
  return fast_search_noavx(array, array_len, index, search_element);
}
#else
template <typename T>
uintptr_t fast_search_avx(T* array, uintptr_t array_len, uintptr_t index,
                          T search_element) {
  UNREACHABLE();
}
#endif  // ifdef __SSE3__

#undef IS_CLANG_WIN
#undef VECTORIZED_LOOP_Neon
#undef VECTORIZED_LOOP_x86

template <typename T>
inline uintptr_t search(T* array, uintptr_t array_len, uintptr_t index,
                        T search_element) {
  if (get_vectorization_kind() == SimdKinds::kAVX2) {
    return fast_search_avx(array, array_len, index, search_element);
  } else {
    return fast_search_noavx(array, array_len, index, search_element);
  }
}

enum class ArrayIndexOfIncludesKind { DOUBLE, OBJECTORSMI };

// ArrayIndexOfIncludes only handles cases that can be efficiently
// vectorized:
//
//   * Searching for a Smi in a Smi array
//
//   * Searching for a Smi or Double in a Double array
//
//   * Searching for an object in an object array.
//
// Other cases should be dealt with either with the CSA builtin or with the
// inlined optimized code.
template <ArrayIndexOfIncludesKind kind>
Address ArrayIndexOfIncludes(Address array_start, uintptr_t array_len,
                             uintptr_t from_index, Address search_element) {
  if (array_len == 0) {
    return Smi::FromInt(-1).ptr();
  }

  if constexpr (kind == ArrayIndexOfIncludesKind::DOUBLE) {
    Tagged<FixedDoubleArray> fixed_array =
        Cast<FixedDoubleArray>(Tagged<Object>(array_start));
    UnalignedDoubleMember* unaligned_array = fixed_array->begin();
    // TODO(leszeks): This reinterpret cast is a bit sketchy because the values
    // are unaligned doubles. Ideally we'd fix the search method to support
    // UnalignedDoubleMember.
    static_assert(sizeof(UnalignedDoubleMember) == sizeof(double));
    double* array = reinterpret_cast<double*>(unaligned_array);

    double search_num;
    if (IsSmi(Tagged<Object>(search_element))) {
      search_num = Tagged<Object>(search_element).ToSmi().value();
    } else {
      DCHECK(IsHeapNumber(Tagged<Object>(search_element)));
      search_num = Cast<HeapNumber>(Tagged<Object>(search_element))->value();
    }

    DCHECK(!std::isnan(search_num));

    if (reinterpret_cast<uintptr_t>(array) % sizeof(double) != 0) {
      // Slow scalar search for unaligned double array.
      for (; from_index < array_len; from_index++) {
        if (fixed_array->is_the_hole(static_cast<int>(from_index))) {
          // |search_num| cannot be NaN, so there is no need to check against
          // holes.
          continue;
        }
        if (fixed_array->get_scalar(static_cast<int>(from_index)) ==
            search_num) {
          return from_index;
        }
      }
      return Smi::FromInt(-1).ptr();
    }

    return search<double>(array, array_len, from_index, search_num);
  }

  if constexpr (kind == ArrayIndexOfIncludesKind::OBJECTORSMI) {
    Tagged<FixedArray> fixed_array =
        Cast<FixedArray>(Tagged<Object>(array_start));
    Tagged_t* array = static_cast<Tagged_t*>(
        fixed_array->RawFieldOfFirstElement().ToVoidPtr());

    DCHECK(!IsHeapNumber(Tagged<Object>(search_element)));
    DCHECK(!IsBigInt(Tagged<Object>(search_element)));
    DCHECK(!IsString(Tagged<Object>(search_element)));

    return search<Tagged_t>(array, array_len, from_index,
                            static_cast<Tagged_t>(search_element));
  }
}

}  // namespace

uintptr_t ArrayIndexOfIncludesSmiOrObject(Address array_start,
                                          uintptr_t array_len,
                                          uintptr_t from_index,
                                          Address search_element) {
  return ArrayIndexOfIncludes<ArrayIndexOfIncludesKind::OBJECTORSMI>(
      array_start, array_len, from_index, search_element);
}

uintptr_t ArrayIndexOfIncludesDouble(Address array_start, uintptr_t array_len,
                                     uintptr_t from_index,
                                     Address search_element) {
  return ArrayIndexOfIncludes<ArrayIndexOfIncludesKind::DOUBLE>(
      array_start, array_len, from_index, search_element);
}

#ifdef NEON64
#undef NEON64
#endif

}  // namespace internal
}  // namespace v8

"""

```