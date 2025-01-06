Response:
Let's break down the thought process for analyzing this header file snippet.

1. **Initial Scan & Keywords:** The first step is a quick read-through, looking for recurring keywords and patterns. Immediately noticeable are: `#ifndef`, `#define`, `#include`, `namespace v8`, `namespace internal`, `class`, `typedef`, `constexpr`, `enum`, `struct`, `template`, `static_assert`, `V8_INLINE`,  and various uppercase identifiers (likely constants or macros). These give a strong hint that this is a low-level C++ header file defining core V8 concepts.

2. **Header Guards:**  The `#ifndef INCLUDE_V8_INTERNAL_H_` and `#define INCLUDE_V8_INTERNAL_H_` clearly indicate header guards to prevent multiple inclusions and compilation errors. This is standard C++ practice.

3. **Includes:** The included standard library headers (`<stddef.h>`, `<stdint.h>`, `<string.h>`, `<atomic>`, etc.) suggest this code deals with fundamental data types, memory management, and potentially threading. The inclusion of `"v8config.h"` is key – it points to configuration settings that influence V8's behavior. The conditional inclusion of `<compare>` hints at support for C++20's three-way comparison operator in newer environments.

4. **Namespaces:** The `namespace v8` and nested `namespace internal` are a strong indicator of modularity and encapsulation within the V8 codebase. Things inside `internal` are likely implementation details not directly exposed to the public V8 API.

5. **Basic Types and Constants:** The definitions of `Address`, `kNullAddress`, `KB`, `MB`, `GB`, and potentially `TB` (architecture-dependent) define fundamental units and constants related to memory. The `kApi...Size` constants reveal the sizes of primitive C++ types as seen by the V8 API.

6. **Tagging Scheme (Crucial Part):**  The section on "Tag information for HeapObject," "fowarding pointers," and "Smi" is critical. This points to V8's internal object representation and how it distinguishes different types of data. The concepts of tags and masks are fundamental for efficient type checking and memory management. The different tag values (`kHeapObjectTag`, `kWeakHeapObjectTag`, `kForwardingTag`, `kSmiTag`) are important to note.

7. **Smi Tagging (Platform-Specific):** The `template <size_t tagged_ptr_size> struct SmiTagging` and the specializations for `SmiTagging<4>` and `SmiTagging<8>` are about handling "Small Integers" (Smis) efficiently. The logic for `SmiToInt` and `IsValidSmi` highlights how Smis are encoded and decoded, and how the range of representable Smis depends on the platform's pointer size.

8. **Pointer Compression:** The `#ifdef V8_COMPRESS_POINTERS` block introduces a significant optimization. The constants like `kPtrComprCageReservationSize` and the change in `kApiTaggedSize` indicate a mechanism to reduce memory usage by using smaller pointers in certain contexts.

9. **Sandbox (Security Focus):** The `#ifdef V8_ENABLE_SANDBOX` section is all about security. The constants like `kSandboxSize`, `kSandboxGuardRegionSize`, `kSandboxedPointerShift`, and the introduction of `SandboxedPointer_t` suggest a sandboxing mechanism to isolate V8's memory and protect against vulnerabilities.

10. **External Pointers (Interfacing with the Outside World):** The definitions of `ExternalPointerHandle`, `ExternalPointer_t`, and the extensive section on external pointer tags and their properties are crucial for understanding how V8 interacts with data outside its managed heap. The discussion of tagging, type safety, and substitution safety underscores the security considerations involved.

11. **External Buffers:** Similar to external pointers, the `ExternalBufferHandle` and `ExternalBuffer_t` definitions relate to managing memory buffers that reside outside the V8 heap.

12. **Macros and Enums for Tags:**  The `#define SHARED_EXTERNAL_POINTER_TAGS(V)` and related macros, along with the `enum ExternalPointerTag`, provide a structured way to define and manage the various tags associated with external pointers. The comments within these definitions offer insights into the purpose of different tag types.

13. **Indirect Pointers (Incomplete Snippet):** The section starting with "Indirect Pointers" is cut off, but the introduction suggests another layer of indirection for referencing objects outside the sandbox, particularly `Code` objects.

14. **Putting It All Together (High-Level Summary):** Based on the identified elements, the file's primary functions are:
    * **Defining core data types and constants:** Fundamental building blocks for V8's memory management.
    * **Implementing a tagging scheme:**  Distinguishing between different object types and values efficiently.
    * **Handling Small Integers (Smis):** Optimizing the representation and manipulation of small integers.
    * **Optionally enabling pointer compression:** Reducing memory footprint.
    * **Optionally enabling sandboxing:** Enhancing security by isolating V8's memory.
    * **Managing external pointers and buffers:**  Providing controlled access to data outside the V8 heap, with a strong focus on type safety and security.

15. **Considering the "Torque" and JavaScript Questions:** The file ends with a `.h` extension, so it's not a Torque file. The file deals with low-level C++ internals, and while these internals *support* JavaScript functionality, there isn't a direct, simple JavaScript example that perfectly illustrates every concept. The tagging scheme is indirectly related to how JavaScript objects are represented, and external pointers are used when interacting with native code, but a direct, concise JavaScript analogy for *everything* is difficult.

16. **Code Logic and Error Examples:**  The code is mostly definitions and constants. The logic lies in *how* these are used elsewhere in the V8 codebase. Potential programming errors are related to misinterpreting or misusing the tagging scheme, handling external pointers incorrectly (leading to dangling pointers or type confusion), or violating sandbox constraints.

This systematic approach, starting with a broad overview and then diving into specific sections, helps to understand the purpose and functionality of a complex header file like `v8-internal.h`.
这是 V8 引擎的内部头文件 `v8-internal.h` 的一部分，它定义了 V8 引擎内部使用的各种类型、常量、宏和数据结构。由于文件扩展名是 `.h` 而不是 `.tq`，它不是 Torque 源代码。

以下是对该代码片段功能的归纳：

**核心功能:**

1. **基本类型定义:** 定义了 V8 内部使用的基本数据类型，如 `Address` (表示内存地址，通常是 `uintptr_t`)，以及表示空地址的常量 `kNullAddress`。
2. **常用大小常量:** 定义了 KB、MB、GB 等常用的大小单位常量，方便代码中使用。
3. **API 大小信息:** 定义了 V8 API 中各种数据类型的大小，例如指针 (`kApiSystemPointerSize`)、double (`kApiDoubleSize`)、int32 (`kApiInt32Size`) 等，这对于处理外部交互和数据布局至关重要。
4. **对象标记 (Tagging):**  定义了 V8 内部对象的标记方案，用于区分不同类型的对象和值，例如 `kHeapObjectTag`、`kWeakHeapObjectTag`、`kForwardingTag` 和 `kSmiTag`。这些标记位于对象或值的低位，允许快速类型检查。
5. **Smi (Small Integer) 处理:** 定义了 Smi 的标记和移位信息 (`kSmiTag`, `kSmiTagSize`, `kSmiShiftSize`)，以及平台相关的 Smi 范围 (`kSmiMinValue`, `kSmiMaxValue`)。Smi 是 V8 中用于高效表示小整数的一种优化手段。
6. **平台相关的 Smi 实现:** 使用模板 `SmiTagging` 针对不同字长的平台（32 位和 64 位）提供了不同的 Smi 处理方式。
7. **指针压缩 (可选):**  定义了与指针压缩相关的常量 (`kPtrComprCageReservationSize`, `kPtrComprCageBaseAlignment`, `kApiTaggedSize`)。指针压缩是一种减少内存使用的优化技术，尤其在 64 位架构上。
8. **沙箱支持 (可选):** 定义了与 V8 沙箱机制相关的常量和类型 (`SandboxIsEnabled`, `SandboxedPointer_t`, `kSandboxSize`, `kSandboxGuardRegionSize` 等)。沙箱是一种安全机制，用于隔离 V8 的内存空间，防止恶意代码访问外部内存。
9. **外部指针管理:** 定义了处理指向 V8 堆外内存的指针的机制，包括 `ExternalPointerHandle` 和 `ExternalPointer_t`。在启用沙箱的情况下，外部指针通常作为句柄存储，以提高安全性。还定义了外部指针表的配置和各种类型的外部指针标签 (`ExternalPointerTag`)。
10. **外部缓冲区管理:** 类似于外部指针，定义了用于管理堆外内存缓冲区的 `ExternalBufferHandle` 和 `ExternalBuffer_t`，以及相关的配置和常量。
11. **CppHeap 指针管理:**  定义了 `CppHeapPointerHandle` 和 `CppHeapPointer_t`，用于管理 C++ 堆上分配的对象指针，这在 V8 内部与 C++ 代码交互时使用。
12. **外部指针标签:**  定义了大量的 `ExternalPointerTag` 枚举值，用于区分不同类型的外部资源，并用于安全性和类型检查。这些标签被组织成宏，方便管理和使用。

**与 JavaScript 的关系 (间接):**

虽然 `v8-internal.h` 是 C++ 代码，但它定义的核心概念直接影响 JavaScript 的执行效率和功能。

* **对象表示:**  `kHeapObjectTag` 等标记与 JavaScript 对象的内部表示方式密切相关。当 V8 执行 JavaScript 代码并创建对象时，这些标记会被使用。
* **小整数优化:** Smi 的处理直接影响 JavaScript 中小整数的性能。V8 能够快速识别和操作 Smi，避免了创建完整的堆对象，从而提高了效率。
* **外部资源交互:** `ExternalPointerHandle` 和相关的机制使得 JavaScript 能够与外部的 C++ 代码或系统资源进行交互，例如通过 Node.js 的原生模块。

**JavaScript 示例 (间接说明):**

虽然不能直接用 JavaScript 代码展示 `v8-internal.h` 中的定义，但可以举例说明其背后的概念：

```javascript
// JavaScript 中创建数字
const smallNumber = 10;
const largeNumber = 10000000000;

// 在 V8 内部，smallNumber 很可能被表示为 Smi，而 largeNumber 则需要
// 更复杂的堆对象表示。

// 与外部 C++ 代码交互 (Node.js 示例)
const addon = require('./my_addon'); // 假设 my_addon 是一个 C++ 插件

// addon 中的 C++ 代码可能会使用 V8 的 API 来创建或操作 JavaScript 对象，
// 这会涉及到 `v8-internal.h` 中定义的类型和常量。
```

**代码逻辑推理 (常量定义，无复杂的逻辑):**

该代码片段主要是常量和类型定义，没有复杂的逻辑推理。

**假设输入与输出 (不适用):**

由于主要是定义，没有输入和输出的概念。

**用户常见的编程错误 (间接相关):**

用户在编写 JavaScript 代码时，通常不会直接与 `v8-internal.h` 交互。但是，了解其背后的概念可以帮助理解一些性能问题或限制：

* **过度使用大整数:** 如果 JavaScript 代码中频繁使用超出 Smi 范围的整数，可能会导致性能下降，因为 V8 需要分配和管理堆对象来表示这些数字。
* **与原生代码交互不当:** 在编写 Node.js 原生模块时，如果错误地使用了 V8 的 C++ API，可能会导致内存泄漏、崩溃等问题。这可能与对 `ExternalPointerHandle` 等概念的错误理解有关。

**功能归纳:**

`v8/include/v8-internal.h` 的这个代码片段定义了 V8 引擎内部运作的关键基础元素，包括基本数据类型、对象标记方案、小整数优化、可选的指针压缩和沙箱机制，以及用于与外部内存和 C++ 代码交互的机制。这些定义是 V8 引擎高效、安全地执行 JavaScript 代码的基石。 它是 V8 内部实现细节的核心组成部分，对于理解 V8 的底层架构至关重要。

Prompt: 
```
这是目录为v8/include/v8-internal.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-internal.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_INTERNAL_H_
#define INCLUDE_V8_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atomic>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <type_traits>

#include "v8config.h"  // NOLINT(build/include_directory)

// TODO(pkasting): Use <compare>/spaceship unconditionally after dropping
// support for old libstdc++ versions.
#if __has_include(<version>)
#include <version>
#endif
#if defined(__cpp_lib_three_way_comparison) &&   \
    __cpp_lib_three_way_comparison >= 201711L && \
    defined(__cpp_lib_concepts) && __cpp_lib_concepts >= 202002L
#include <compare>
#include <concepts>

#define V8_HAVE_SPACESHIP_OPERATOR 1
#else
#define V8_HAVE_SPACESHIP_OPERATOR 0
#endif

namespace v8 {

class Array;
class Context;
class Data;
class Isolate;

namespace internal {

class Heap;
class LocalHeap;
class Isolate;
class LocalIsolate;

typedef uintptr_t Address;
static constexpr Address kNullAddress = 0;

constexpr int KB = 1024;
constexpr int MB = KB * 1024;
constexpr int GB = MB * 1024;
#ifdef V8_TARGET_ARCH_X64
constexpr size_t TB = size_t{GB} * 1024;
#endif

/**
 * Configuration of tagging scheme.
 */
const int kApiSystemPointerSize = sizeof(void*);
const int kApiDoubleSize = sizeof(double);
const int kApiInt32Size = sizeof(int32_t);
const int kApiInt64Size = sizeof(int64_t);
const int kApiSizetSize = sizeof(size_t);

// Tag information for HeapObject.
const int kHeapObjectTag = 1;
const int kWeakHeapObjectTag = 3;
const int kHeapObjectTagSize = 2;
const intptr_t kHeapObjectTagMask = (1 << kHeapObjectTagSize) - 1;
const intptr_t kHeapObjectReferenceTagMask = 1 << (kHeapObjectTagSize - 1);

// Tag information for fowarding pointers stored in object headers.
// 0b00 at the lowest 2 bits in the header indicates that the map word is a
// forwarding pointer.
const int kForwardingTag = 0;
const int kForwardingTagSize = 2;
const intptr_t kForwardingTagMask = (1 << kForwardingTagSize) - 1;

// Tag information for Smi.
const int kSmiTag = 0;
const int kSmiTagSize = 1;
const intptr_t kSmiTagMask = (1 << kSmiTagSize) - 1;

template <size_t tagged_ptr_size>
struct SmiTagging;

constexpr intptr_t kIntptrAllBitsSet = intptr_t{-1};
constexpr uintptr_t kUintptrAllBitsSet =
    static_cast<uintptr_t>(kIntptrAllBitsSet);

// Smi constants for systems where tagged pointer is a 32-bit value.
template <>
struct SmiTagging<4> {
  enum { kSmiShiftSize = 0, kSmiValueSize = 31 };

  static constexpr intptr_t kSmiMinValue =
      static_cast<intptr_t>(kUintptrAllBitsSet << (kSmiValueSize - 1));
  static constexpr intptr_t kSmiMaxValue = -(kSmiMinValue + 1);

  V8_INLINE static constexpr int SmiToInt(Address value) {
    int shift_bits = kSmiTagSize + kSmiShiftSize;
    // Truncate and shift down (requires >> to be sign extending).
    return static_cast<int32_t>(static_cast<uint32_t>(value)) >> shift_bits;
  }

  template <class T, typename std::enable_if_t<std::is_integral_v<T> &&
                                               std::is_signed_v<T>>* = nullptr>
  V8_INLINE static constexpr bool IsValidSmi(T value) {
    // Is value in range [kSmiMinValue, kSmiMaxValue].
    // Use unsigned operations in order to avoid undefined behaviour in case of
    // signed integer overflow.
    return (static_cast<uintptr_t>(value) -
            static_cast<uintptr_t>(kSmiMinValue)) <=
           (static_cast<uintptr_t>(kSmiMaxValue) -
            static_cast<uintptr_t>(kSmiMinValue));
  }

  template <class T,
            typename std::enable_if_t<std::is_integral_v<T> &&
                                      std::is_unsigned_v<T>>* = nullptr>
  V8_INLINE static constexpr bool IsValidSmi(T value) {
    static_assert(kSmiMaxValue <= std::numeric_limits<uintptr_t>::max());
    return value <= static_cast<uintptr_t>(kSmiMaxValue);
  }

  // Same as the `intptr_t` version but works with int64_t on 32-bit builds
  // without slowing down anything else.
  V8_INLINE static constexpr bool IsValidSmi(int64_t value) {
    return (static_cast<uint64_t>(value) -
            static_cast<uint64_t>(kSmiMinValue)) <=
           (static_cast<uint64_t>(kSmiMaxValue) -
            static_cast<uint64_t>(kSmiMinValue));
  }

  V8_INLINE static constexpr bool IsValidSmi(uint64_t value) {
    static_assert(kSmiMaxValue <= std::numeric_limits<uint64_t>::max());
    return value <= static_cast<uint64_t>(kSmiMaxValue);
  }
};

// Smi constants for systems where tagged pointer is a 64-bit value.
template <>
struct SmiTagging<8> {
  enum { kSmiShiftSize = 31, kSmiValueSize = 32 };

  static constexpr intptr_t kSmiMinValue =
      static_cast<intptr_t>(kUintptrAllBitsSet << (kSmiValueSize - 1));
  static constexpr intptr_t kSmiMaxValue = -(kSmiMinValue + 1);

  V8_INLINE static constexpr int SmiToInt(Address value) {
    int shift_bits = kSmiTagSize + kSmiShiftSize;
    // Shift down and throw away top 32 bits.
    return static_cast<int>(static_cast<intptr_t>(value) >> shift_bits);
  }

  template <class T, typename std::enable_if_t<std::is_integral_v<T> &&
                                               std::is_signed_v<T>>* = nullptr>
  V8_INLINE static constexpr bool IsValidSmi(T value) {
    // To be representable as a long smi, the value must be a 32-bit integer.
    return std::numeric_limits<int32_t>::min() <= value &&
           value <= std::numeric_limits<int32_t>::max();
  }

  template <class T,
            typename std::enable_if_t<std::is_integral_v<T> &&
                                      std::is_unsigned_v<T>>* = nullptr>
  V8_INLINE static constexpr bool IsValidSmi(T value) {
    return value <= std::numeric_limits<int32_t>::max();
  }
};

#ifdef V8_COMPRESS_POINTERS
// See v8:7703 or src/common/ptr-compr-inl.h for details about pointer
// compression.
constexpr size_t kPtrComprCageReservationSize = size_t{1} << 32;
constexpr size_t kPtrComprCageBaseAlignment = size_t{1} << 32;

static_assert(
    kApiSystemPointerSize == kApiInt64Size,
    "Pointer compression can be enabled only for 64-bit architectures");
const int kApiTaggedSize = kApiInt32Size;
#else
const int kApiTaggedSize = kApiSystemPointerSize;
#endif

constexpr bool PointerCompressionIsEnabled() {
  return kApiTaggedSize != kApiSystemPointerSize;
}

#ifdef V8_31BIT_SMIS_ON_64BIT_ARCH
using PlatformSmiTagging = SmiTagging<kApiInt32Size>;
#else
using PlatformSmiTagging = SmiTagging<kApiTaggedSize>;
#endif

// TODO(ishell): Consinder adding kSmiShiftBits = kSmiShiftSize + kSmiTagSize
// since it's used much more often than the inividual constants.
const int kSmiShiftSize = PlatformSmiTagging::kSmiShiftSize;
const int kSmiValueSize = PlatformSmiTagging::kSmiValueSize;
const int kSmiMinValue = static_cast<int>(PlatformSmiTagging::kSmiMinValue);
const int kSmiMaxValue = static_cast<int>(PlatformSmiTagging::kSmiMaxValue);
constexpr bool SmiValuesAre31Bits() { return kSmiValueSize == 31; }
constexpr bool SmiValuesAre32Bits() { return kSmiValueSize == 32; }
constexpr bool Is64() { return kApiSystemPointerSize == sizeof(int64_t); }

V8_INLINE static constexpr Address IntToSmi(int value) {
  return (static_cast<Address>(value) << (kSmiTagSize + kSmiShiftSize)) |
         kSmiTag;
}

/*
 * Sandbox related types, constants, and functions.
 */
constexpr bool SandboxIsEnabled() {
#ifdef V8_ENABLE_SANDBOX
  return true;
#else
  return false;
#endif
}

// SandboxedPointers are guaranteed to point into the sandbox. This is achieved
// for example by storing them as offset rather than as raw pointers.
using SandboxedPointer_t = Address;

#ifdef V8_ENABLE_SANDBOX

// Size of the sandbox, excluding the guard regions surrounding it.
#if defined(V8_TARGET_OS_ANDROID)
// On Android, most 64-bit devices seem to be configured with only 39 bits of
// virtual address space for userspace. As such, limit the sandbox to 128GB (a
// quarter of the total available address space).
constexpr size_t kSandboxSizeLog2 = 37;  // 128 GB
#else
// Everywhere else use a 1TB sandbox.
constexpr size_t kSandboxSizeLog2 = 40;  // 1 TB
#endif  // V8_TARGET_OS_ANDROID
constexpr size_t kSandboxSize = 1ULL << kSandboxSizeLog2;

// Required alignment of the sandbox. For simplicity, we require the
// size of the guard regions to be a multiple of this, so that this specifies
// the alignment of the sandbox including and excluding surrounding guard
// regions. The alignment requirement is due to the pointer compression cage
// being located at the start of the sandbox.
constexpr size_t kSandboxAlignment = kPtrComprCageBaseAlignment;

// Sandboxed pointers are stored inside the heap as offset from the sandbox
// base shifted to the left. This way, it is guaranteed that the offset is
// smaller than the sandbox size after shifting it to the right again. This
// constant specifies the shift amount.
constexpr uint64_t kSandboxedPointerShift = 64 - kSandboxSizeLog2;

// Size of the guard regions surrounding the sandbox. This assumes a worst-case
// scenario of a 32-bit unsigned index used to access an array of 64-bit
// values.
constexpr size_t kSandboxGuardRegionSize = 32ULL * GB;

static_assert((kSandboxGuardRegionSize % kSandboxAlignment) == 0,
              "The size of the guard regions around the sandbox must be a "
              "multiple of its required alignment.");

// On OSes where reserving virtual memory is too expensive to reserve the
// entire address space backing the sandbox, notably Windows pre 8.1, we create
// a partially reserved sandbox that doesn't actually reserve most of the
// memory, and so doesn't have the desired security properties as unrelated
// memory allocations could end up inside of it, but which still ensures that
// objects that should be located inside the sandbox are allocated within
// kSandboxSize bytes from the start of the sandbox. The minimum size of the
// region that is actually reserved for such a sandbox is specified by this
// constant and should be big enough to contain the pointer compression cage as
// well as the ArrayBuffer partition.
constexpr size_t kSandboxMinimumReservationSize = 8ULL * GB;

static_assert(kSandboxMinimumReservationSize > kPtrComprCageReservationSize,
              "The minimum reservation size for a sandbox must be larger than "
              "the pointer compression cage contained within it.");

// The maximum buffer size allowed inside the sandbox. This is mostly dependent
// on the size of the guard regions around the sandbox: an attacker must not be
// able to construct a buffer that appears larger than the guard regions and
// thereby "reach out of" the sandbox.
constexpr size_t kMaxSafeBufferSizeForSandbox = 32ULL * GB - 1;
static_assert(kMaxSafeBufferSizeForSandbox <= kSandboxGuardRegionSize,
              "The maximum allowed buffer size must not be larger than the "
              "sandbox's guard regions");

constexpr size_t kBoundedSizeShift = 29;
static_assert(1ULL << (64 - kBoundedSizeShift) ==
                  kMaxSafeBufferSizeForSandbox + 1,
              "The maximum size of a BoundedSize must be synchronized with the "
              "kMaxSafeBufferSizeForSandbox");

#endif  // V8_ENABLE_SANDBOX

#ifdef V8_COMPRESS_POINTERS

#ifdef V8_TARGET_OS_ANDROID
// The size of the virtual memory reservation for an external pointer table.
// This determines the maximum number of entries in a table. Using a maximum
// size allows omitting bounds checks on table accesses if the indices are
// guaranteed (e.g. through shifting) to be below the maximum index. This
// value must be a power of two.
constexpr size_t kExternalPointerTableReservationSize = 256 * MB;

// The external pointer table indices stored in HeapObjects as external
// pointers are shifted to the left by this amount to guarantee that they are
// smaller than the maximum table size even after the C++ compiler multiplies
// them by 8 to be used as indexes into a table of 64 bit pointers.
constexpr uint32_t kExternalPointerIndexShift = 7;
#else
constexpr size_t kExternalPointerTableReservationSize = 512 * MB;
constexpr uint32_t kExternalPointerIndexShift = 6;
#endif  // V8_TARGET_OS_ANDROID

// The maximum number of entries in an external pointer table.
constexpr int kExternalPointerTableEntrySize = 8;
constexpr int kExternalPointerTableEntrySizeLog2 = 3;
constexpr size_t kMaxExternalPointers =
    kExternalPointerTableReservationSize / kExternalPointerTableEntrySize;
static_assert((1 << (32 - kExternalPointerIndexShift)) == kMaxExternalPointers,
              "kExternalPointerTableReservationSize and "
              "kExternalPointerIndexShift don't match");

#else  // !V8_COMPRESS_POINTERS

// Needed for the V8.SandboxedExternalPointersCount histogram.
constexpr size_t kMaxExternalPointers = 0;

#endif  // V8_COMPRESS_POINTERS

// A ExternalPointerHandle represents a (opaque) reference to an external
// pointer that can be stored inside the sandbox. A ExternalPointerHandle has
// meaning only in combination with an (active) Isolate as it references an
// external pointer stored in the currently active Isolate's
// ExternalPointerTable. Internally, an ExternalPointerHandles is simply an
// index into an ExternalPointerTable that is shifted to the left to guarantee
// that it is smaller than the size of the table.
using ExternalPointerHandle = uint32_t;

// ExternalPointers point to objects located outside the sandbox. When the V8
// sandbox is enabled, these are stored on heap as ExternalPointerHandles,
// otherwise they are simply raw pointers.
#ifdef V8_ENABLE_SANDBOX
using ExternalPointer_t = ExternalPointerHandle;
#else
using ExternalPointer_t = Address;
#endif

constexpr ExternalPointer_t kNullExternalPointer = 0;
constexpr ExternalPointerHandle kNullExternalPointerHandle = 0;

// See `ExternalPointerHandle` for the main documentation. The difference to
// `ExternalPointerHandle` is that the handle does not represent an arbitrary
// external pointer but always refers to an object managed by `CppHeap`. The
// handles are using in combination with a dedicated table for `CppHeap`
// references.
using CppHeapPointerHandle = uint32_t;

// The actual pointer to objects located on the `CppHeap`. When pointer
// compression is enabled these pointers are stored as `CppHeapPointerHandle`.
// In non-compressed configurations the pointers are simply stored as raw
// pointers.
#ifdef V8_COMPRESS_POINTERS
using CppHeapPointer_t = CppHeapPointerHandle;
#else
using CppHeapPointer_t = Address;
#endif

constexpr CppHeapPointer_t kNullCppHeapPointer = 0;
constexpr CppHeapPointerHandle kNullCppHeapPointerHandle = 0;

constexpr uint64_t kCppHeapPointerMarkBit = 1ULL;
constexpr uint64_t kCppHeapPointerTagShift = 1;
constexpr uint64_t kCppHeapPointerPayloadShift = 16;

#ifdef V8_COMPRESS_POINTERS
// CppHeapPointers use a dedicated pointer table. These constants control the
// size and layout of the table. See the corresponding constants for the
// external pointer table for further details.
constexpr size_t kCppHeapPointerTableReservationSize =
    kExternalPointerTableReservationSize;
constexpr uint32_t kCppHeapPointerIndexShift = kExternalPointerIndexShift;

constexpr int kCppHeapPointerTableEntrySize = 8;
constexpr int kCppHeapPointerTableEntrySizeLog2 = 3;
constexpr size_t kMaxCppHeapPointers =
    kCppHeapPointerTableReservationSize / kCppHeapPointerTableEntrySize;
static_assert((1 << (32 - kCppHeapPointerIndexShift)) == kMaxCppHeapPointers,
              "kCppHeapPointerTableReservationSize and "
              "kCppHeapPointerIndexShift don't match");

#else  // !V8_COMPRESS_POINTERS

// Needed for the V8.SandboxedCppHeapPointersCount histogram.
constexpr size_t kMaxCppHeapPointers = 0;

#endif  // V8_COMPRESS_POINTERS

// See `ExternalPointerHandle` for the main documentation. The difference to
// `ExternalPointerHandle` is that the handle always refers to a
// (external pointer, size) tuple. The handles are used in combination with a
// dedicated external buffer table (EBT).
using ExternalBufferHandle = uint32_t;

// ExternalBuffer point to buffer located outside the sandbox. When the V8
// sandbox is enabled, these are stored on heap as ExternalBufferHandles,
// otherwise they are simply raw pointers.
#ifdef V8_ENABLE_SANDBOX
using ExternalBuffer_t = ExternalBufferHandle;
#else
using ExternalBuffer_t = Address;
#endif

#ifdef V8_TARGET_OS_ANDROID
// The size of the virtual memory reservation for the external buffer table.
// As with the external pointer table, a maximum table size in combination with
// shifted indices allows omitting bounds checks.
constexpr size_t kExternalBufferTableReservationSize = 64 * MB;

// The external buffer handles are stores shifted to the left by this amount
// to guarantee that they are smaller than the maximum table size.
constexpr uint32_t kExternalBufferHandleShift = 10;
#else
constexpr size_t kExternalBufferTableReservationSize = 128 * MB;
constexpr uint32_t kExternalBufferHandleShift = 9;
#endif  // V8_TARGET_OS_ANDROID

// A null handle always references an entry that contains nullptr.
constexpr ExternalBufferHandle kNullExternalBufferHandle = 0;

// The maximum number of entries in an external buffer table.
constexpr int kExternalBufferTableEntrySize = 16;
constexpr int kExternalBufferTableEntrySizeLog2 = 4;
constexpr size_t kMaxExternalBufferPointers =
    kExternalBufferTableReservationSize / kExternalBufferTableEntrySize;
static_assert((1 << (32 - kExternalBufferHandleShift)) ==
                  kMaxExternalBufferPointers,
              "kExternalBufferTableReservationSize and "
              "kExternalBufferHandleShift don't match");

//
// External Pointers.
//
// When the sandbox is enabled, external pointers are stored in an external
// pointer table and are referenced from HeapObjects through an index (a
// "handle"). When stored in the table, the pointers are tagged with per-type
// tags to prevent type confusion attacks between different external objects.
// Besides type information bits, these tags also contain the GC marking bit
// which indicates whether the pointer table entry is currently alive. When a
// pointer is written into the table, the tag is ORed into the top bits. When
// that pointer is later loaded from the table, it is ANDed with the inverse of
// the expected tag. If the expected and actual type differ, this will leave
// some of the top bits of the pointer set, rendering the pointer inaccessible.
// The AND operation also removes the GC marking bit from the pointer.
//
// The tags are constructed such that UNTAG(TAG(0, T1), T2) != 0 for any two
// (distinct) tags T1 and T2. In practice, this is achieved by generating tags
// that all have the same number of zeroes and ones but different bit patterns.
// With N type tag bits, this allows for (N choose N/2) possible type tags.
// Besides the type tag bits, the tags also have the GC marking bit set so that
// the marking bit is automatically set when a pointer is written into the
// external pointer table (in which case it is clearly alive) and is cleared
// when the pointer is loaded. The exception to this is the free entry tag,
// which doesn't have the mark bit set, as the entry is not alive. This
// construction allows performing the type check and removing GC marking bits
// from the pointer in one efficient operation (bitwise AND). The number of
// available bits is limited in the following way: on x64, bits [47, 64) are
// generally available for tagging (userspace has 47 address bits available).
// On Arm64, userspace typically has a 40 or 48 bit address space. However, due
// to top-byte ignore (TBI) and memory tagging (MTE), the top byte is unusable
// for type checks as type-check failures would go unnoticed or collide with
// MTE bits. Some bits of the top byte can, however, still be used for the GC
// marking bit. The bits available for the type tags are therefore limited to
// [48, 56), i.e. (8 choose 4) = 70 different types.
// The following options exist to increase the number of possible types:
// - Using multiple ExternalPointerTables since tags can safely be reused
//   across different tables
// - Using "extended" type checks, where additional type information is stored
//   either in an adjacent pointer table entry or at the pointed-to location
// - Using a different tagging scheme, for example based on XOR which would
//   allow for 2**8 different tags but require a separate operation to remove
//   the marking bit
//
// The external pointer sandboxing mechanism ensures that every access to an
// external pointer field will result in a valid pointer of the expected type
// even in the presence of an attacker able to corrupt memory inside the
// sandbox. However, if any data related to the external object is stored
// inside the sandbox it may still be corrupted and so must be validated before
// use or moved into the external object. Further, an attacker will always be
// able to substitute different external pointers of the same type for each
// other. Therefore, code using external pointers must be written in a
// "substitution-safe" way, i.e. it must always be possible to substitute
// external pointers of the same type without causing memory corruption outside
// of the sandbox. Generally this is achieved by referencing any group of
// related external objects through a single external pointer.
//
// Currently we use bit 62 for the marking bit which should always be unused as
// it's part of the non-canonical address range. When Arm's top-byte ignore
// (TBI) is enabled, this bit will be part of the ignored byte, and we assume
// that the Embedder is not using this byte (really only this one bit) for any
// other purpose. This bit also does not collide with the memory tagging
// extension (MTE) which would use bits [56, 60).
//
// External pointer tables are also available even when the sandbox is off but
// pointer compression is on. In that case, the mechanism can be used to ease
// alignment requirements as it turns unaligned 64-bit raw pointers into
// aligned 32-bit indices. To "opt-in" to the external pointer table mechanism
// for this purpose, instead of using the ExternalPointer accessors one needs to
// use ExternalPointerHandles directly and use them to access the pointers in an
// ExternalPointerTable.
constexpr uint64_t kExternalPointerMarkBit = 1ULL << 62;
constexpr uint64_t kExternalPointerTagMask = 0x40ff000000000000;
constexpr uint64_t kExternalPointerTagMaskWithoutMarkBit = 0xff000000000000;
constexpr uint64_t kExternalPointerTagShift = 48;

// All possible 8-bit type tags.
// These are sorted so that tags can be grouped together and it can efficiently
// be checked if a tag belongs to a given group. See for example the
// IsSharedExternalPointerType routine.
constexpr uint64_t kAllTagsForAndBasedTypeChecking[] = {
    0b00001111, 0b00010111, 0b00011011, 0b00011101, 0b00011110, 0b00100111,
    0b00101011, 0b00101101, 0b00101110, 0b00110011, 0b00110101, 0b00110110,
    0b00111001, 0b00111010, 0b00111100, 0b01000111, 0b01001011, 0b01001101,
    0b01001110, 0b01010011, 0b01010101, 0b01010110, 0b01011001, 0b01011010,
    0b01011100, 0b01100011, 0b01100101, 0b01100110, 0b01101001, 0b01101010,
    0b01101100, 0b01110001, 0b01110010, 0b01110100, 0b01111000, 0b10000111,
    0b10001011, 0b10001101, 0b10001110, 0b10010011, 0b10010101, 0b10010110,
    0b10011001, 0b10011010, 0b10011100, 0b10100011, 0b10100101, 0b10100110,
    0b10101001, 0b10101010, 0b10101100, 0b10110001, 0b10110010, 0b10110100,
    0b10111000, 0b11000011, 0b11000101, 0b11000110, 0b11001001, 0b11001010,
    0b11001100, 0b11010001, 0b11010010, 0b11010100, 0b11011000, 0b11100001,
    0b11100010, 0b11100100, 0b11101000, 0b11110000};

#define TAG(i)                                                        \
  ((kAllTagsForAndBasedTypeChecking[i] << kExternalPointerTagShift) | \
   kExternalPointerMarkBit)

// clang-format off

// When adding new tags, please ensure that the code using these tags is
// "substitution-safe", i.e. still operate safely if external pointers of the
// same type are swapped by an attacker. See comment above for more details.

// Shared external pointers are owned by the shared Isolate and stored in the
// shared external pointer table associated with that Isolate, where they can
// be accessed from multiple threads at the same time. The objects referenced
// in this way must therefore always be thread-safe.
#define SHARED_EXTERNAL_POINTER_TAGS(V)                 \
  V(kFirstSharedTag,                            TAG(0)) \
  V(kWaiterQueueNodeTag,                        TAG(0)) \
  V(kExternalStringResourceTag,                 TAG(1)) \
  V(kExternalStringResourceDataTag,             TAG(2)) \
  V(kLastSharedTag,                             TAG(2))
  // Leave some space in the tag range here for future shared tags.

// External pointers using these tags are kept in a per-Isolate external
// pointer table and can only be accessed when this Isolate is active.
#define PER_ISOLATE_EXTERNAL_POINTER_TAGS(V)             \
  V(kNativeContextMicrotaskQueueTag,            TAG(5)) \
  V(kEmbedderDataSlotPayloadTag,                TAG(6)) \
/* This tag essentially stands for a `void*` pointer in the V8 API, and */ \
/* it is the Embedder's responsibility to ensure type safety (against */   \
/* substitution) and lifetime validity of these objects. */                \
  V(kExternalObjectValueTag,                    TAG(7)) \
  V(kFunctionTemplateInfoCallbackTag,           TAG(8)) \
  V(kAccessorInfoGetterTag,                     TAG(9)) \
  V(kAccessorInfoSetterTag,                     TAG(10)) \
  V(kWasmInternalFunctionCallTargetTag,         TAG(11)) \
  V(kWasmTypeInfoNativeTypeTag,                 TAG(12)) \
  V(kWasmExportedFunctionDataSignatureTag,      TAG(13)) \
  V(kWasmContinuationJmpbufTag,                 TAG(14)) \
  V(kWasmStackMemoryTag,                        TAG(15)) \
  V(kWasmIndirectFunctionTargetTag,             TAG(16)) \
  /* Foreigns */ \
  V(kGenericForeignTag,                         TAG(20)) \
  V(kApiNamedPropertyQueryCallbackTag,          TAG(21)) \
  V(kApiNamedPropertyGetterCallbackTag,         TAG(22)) \
  V(kApiNamedPropertySetterCallbackTag,         TAG(23)) \
  V(kApiNamedPropertyDescriptorCallbackTag,     TAG(24)) \
  V(kApiNamedPropertyDefinerCallbackTag,        TAG(25)) \
  V(kApiNamedPropertyDeleterCallbackTag,        TAG(26)) \
  V(kApiIndexedPropertyQueryCallbackTag,        TAG(27)) \
  V(kApiIndexedPropertyGetterCallbackTag,       TAG(28)) \
  V(kApiIndexedPropertySetterCallbackTag,       TAG(29)) \
  V(kApiIndexedPropertyDescriptorCallbackTag,   TAG(30)) \
  V(kApiIndexedPropertyDefinerCallbackTag,      TAG(31)) \
  V(kApiIndexedPropertyDeleterCallbackTag,      TAG(32)) \
  V(kApiIndexedPropertyEnumeratorCallbackTag,   TAG(33)) \
  V(kApiAccessCheckCallbackTag,                 TAG(34)) \
  V(kApiAbortScriptExecutionCallbackTag,        TAG(35)) \
  V(kSyntheticModuleTag,                        TAG(36)) \
  V(kMicrotaskCallbackTag,                      TAG(37)) \
  V(kMicrotaskCallbackDataTag,                  TAG(38)) \
  V(kCFunctionTag,                              TAG(39)) \
  V(kCFunctionInfoTag,                          TAG(40)) \
  V(kMessageListenerTag,                        TAG(41)) \
  V(kWaiterQueueForeignTag,                     TAG(42)) \
  /* Managed */ \
  V(kFirstManagedResourceTag,                   TAG(50)) \
  V(kGenericManagedTag,                         TAG(50)) \
  V(kWasmWasmStreamingTag,                      TAG(51)) \
  V(kWasmFuncDataTag,                           TAG(52)) \
  V(kWasmManagedDataTag,                        TAG(53)) \
  V(kWasmNativeModuleTag,                       TAG(54)) \
  V(kIcuBreakIteratorTag,                       TAG(55)) \
  V(kIcuUnicodeStringTag,                       TAG(56)) \
  V(kIcuListFormatterTag,                       TAG(57)) \
  V(kIcuLocaleTag,                              TAG(58)) \
  V(kIcuSimpleDateFormatTag,                    TAG(59)) \
  V(kIcuDateIntervalFormatTag,                  TAG(60)) \
  V(kIcuRelativeDateTimeFormatterTag,           TAG(61)) \
  V(kIcuLocalizedNumberFormatterTag,            TAG(62)) \
  V(kIcuPluralRulesTag,                         TAG(63)) \
  V(kIcuCollatorTag,                            TAG(64)) \
  V(kDisplayNamesInternalTag,                   TAG(65)) \
  /* External resources whose lifetime is tied to */     \
  /* their entry in the external pointer table but */    \
  /* which are not referenced via a Managed */           \
  V(kArrayBufferExtensionTag,                   TAG(66)) \
  V(kLastManagedResourceTag,                    TAG(66)) \

// All external pointer tags.
#define ALL_EXTERNAL_POINTER_TAGS(V) \
  SHARED_EXTERNAL_POINTER_TAGS(V)    \
  PER_ISOLATE_EXTERNAL_POINTER_TAGS(V)

#define EXTERNAL_POINTER_TAG_ENUM(Name, Tag) Name = Tag,
#define MAKE_TAG(HasMarkBit, TypeTag)                             \
  ((static_cast<uint64_t>(TypeTag) << kExternalPointerTagShift) | \
  (HasMarkBit ? kExternalPointerMarkBit : 0))
enum ExternalPointerTag : uint64_t {
  // Empty tag value. Mostly used as placeholder.
  kExternalPointerNullTag =            MAKE_TAG(1, 0b00000000),
  // External pointer tag that will match any external pointer. Use with care!
  kAnyExternalPointerTag =             MAKE_TAG(1, 0b11111111),
  // External pointer tag that will match any external pointer in a Foreign.
  // Use with care! If desired, this could be made more fine-granular.
  kAnyForeignTag =                     kAnyExternalPointerTag,
  // The free entry tag has all type bits set so every type check with a
  // different type fails. It also doesn't have the mark bit set as free
  // entries are (by definition) not alive.
  kExternalPointerFreeEntryTag =       MAKE_TAG(0, 0b11111111),
  // Evacuation entries are used during external pointer table compaction.
  kExternalPointerEvacuationEntryTag = MAKE_TAG(1, 0b11111110),
  // Tag for zapped/invalidated entries. Those are considered to no longer be
  // in use and so have the marking bit cleared.
  kExternalPointerZappedEntryTag =     MAKE_TAG(0, 0b11111101),

  ALL_EXTERNAL_POINTER_TAGS(EXTERNAL_POINTER_TAG_ENUM)
};

#undef MAKE_TAG
#undef TAG
#undef EXTERNAL_POINTER_TAG_ENUM

// clang-format on

// True if the external pointer must be accessed from the shared isolate's
// external pointer table.
V8_INLINE static constexpr bool IsSharedExternalPointerType(
    ExternalPointerTag tag) {
  return tag >= kFirstSharedTag && tag <= kLastSharedTag;
}

// True if the external pointer may live in a read-only object, in which case
// the table entry will be in the shared read-only segment of the external
// pointer table.
V8_INLINE static constexpr bool IsMaybeReadOnlyExternalPointerType(
    ExternalPointerTag tag) {
  return tag == kAccessorInfoGetterTag || tag == kAccessorInfoSetterTag ||
         tag == kFunctionTemplateInfoCallbackTag;
}

// True if the external pointer references an external object whose lifetime is
// tied to the entry in the external pointer table.
// In this case, the entry in the ExternalPointerTable always points to an
// object derived from ExternalPointerTable::ManagedResource.
V8_INLINE static constexpr bool IsManagedExternalPointerType(
    ExternalPointerTag tag) {
  return tag >= kFirstManagedResourceTag && tag <= kLastManagedResourceTag;
}

// Sanity checks.
#define CHECK_SHARED_EXTERNAL_POINTER_TAGS(Tag, ...) \
  static_assert(IsSharedExternalPointerType(Tag));
#define CHECK_NON_SHARED_EXTERNAL_POINTER_TAGS(Tag, ...) \
  static_assert(!IsSharedExternalPointerType(Tag));

SHARED_EXTERNAL_POINTER_TAGS(CHECK_SHARED_EXTERNAL_POINTER_TAGS)
PER_ISOLATE_EXTERNAL_POINTER_TAGS(CHECK_NON_SHARED_EXTERNAL_POINTER_TAGS)

#undef CHECK_NON_SHARED_EXTERNAL_POINTER_TAGS
#undef CHECK_SHARED_EXTERNAL_POINTER_TAGS

#undef SHARED_EXTERNAL_POINTER_TAGS
#undef EXTERNAL_POINTER_TAGS

//
// Indirect Pointers.
//
// When the sandbox is enabled, indirect pointers are used to reference
// HeapObjects that live outside of the sandbox (but are still managed by V8's
// garbage collector). When object A references an object B through an indirect
// pointer, object A will contain a IndirectPointerHandle, i.e. a shifted
// 32-bit index, which identifies an entry in a pointer table (either the
// trusted pointer table for TrustedObjects, or the code pointer table if it is
// a Code object). This table entry then contains the actual pointer to object
// B. Further, object B owns this pointer table entry, and it is responsible
// for updating the "self-pointer" in the entry when it is relocated in memory.
// This wa
"""


```