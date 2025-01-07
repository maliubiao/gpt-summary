Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/heap/code-range.cc` and how it relates to JavaScript, with a JavaScript example.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for recurring terms and key concepts. Words like "CodeRange," "allocation," "memory," "hint," "preferred region," "builtins," "JIT," "executable," "permissions," and "free" stand out. These provide a high-level idea of what the code is doing.

3. **Section-by-Section Analysis:**  Go through the code more carefully, section by section, paying attention to the details within each function and the overall structure.

    * **Includes:** Notice the included headers. These hint at dependencies on memory management (`<algorithm>`, `<atomic>`, etc.), OS interaction (`"src/base/os.h"` indirectly), and V8 internals (`"src/heap/heap-inl.h"`).

    * **Namespaces:** Identify the `v8::internal` namespace. This indicates that this code is part of V8's internal implementation.

    * **Lazy Initialization:** The `DEFINE_LAZY_LEAKY_OBJECT_GETTER` for `CodeRangeAddressHint` suggests a singleton pattern for managing address hints.

    * **`CodeRangeAddressHint`:** Analyze the `GetAddressHint` and `NotifyFreedCodeRange` methods. These are clearly about managing and providing hints for where to allocate memory for code. The "preferred region" logic and the handling of recently freed regions are important details.

    * **`CodeRange` Class:**  This is the core of the file.
        * **`GetWritableReservedAreaSize`:** This likely relates to a small, writable area at the start of a code range, potentially for storing metadata.
        * **`InitReservation`:** This is a crucial function. It deals with allocating a block of memory for code. Key aspects include:
            * Handling `V8_EXTERNAL_CODE_SPACE_BOOL`.
            * Setting memory permissions (NoAccess, WillJitLater, ReadWriteExecute).
            * Trying to allocate within a "preferred region" near existing code (builtins).
            * Fallback allocation if the preferred region fails.
            * Handling reserved areas at the beginning of the range (especially on Windows).
            * Potentially pre-committing or discarding pages.
        * **`GetPreferredRegion`:**  Understand how the preferred region is calculated based on the location of builtins and potentially the 4GB boundary. The comments explaining requirements (a) and (b) are key.
        * **`Free`:**  Simple deallocation and notifying the `CodeRangeAddressHint`.
        * **`RemapEmbeddedBuiltins`:** This function is about potentially relocating the V8 built-in functions into the allocated code range. The logic involving `AllocatePages`, `RemapPages` (if supported), and setting permissions is significant. The comment about saving memory by remapping is a vital insight.

4. **Identify Core Functionality:** Based on the analysis, the central purpose of `code-range.cc` is to manage the allocation and deallocation of memory regions specifically for storing generated machine code (JIT code, builtins). This involves:

    * **Finding Suitable Memory:**  Strategically searching for memory, ideally near existing code for performance reasons (PC-relative addressing).
    * **Setting Permissions:**  Managing memory permissions to control when code is writable, executable, or inaccessible.
    * **Optimizations:**  Considering factors like pointer compression and trying harder to allocate in preferred regions.
    * **Handling Builtins:**  Potentially relocating or remapping V8's core built-in functions.

5. **Connect to JavaScript:**  The key link to JavaScript is the Just-In-Time (JIT) compilation process. JavaScript code is dynamically compiled into machine code, and this machine code needs to be stored somewhere in memory. The `CodeRange` is the mechanism V8 uses for this. Also, the "builtins" are fundamental JavaScript functions implemented in C++ and exposed to JavaScript.

6. **Formulate the Summary:**  Synthesize the information gathered into a concise summary that captures the main functions and their purpose. Use clear and understandable language, avoiding overly technical jargon where possible. Highlight the relationship to JIT compilation and builtins.

7. **Create the JavaScript Example:**  Think about a simple JavaScript scenario that demonstrates the impact of code generation. A basic function that gets executed multiple times, allowing the JIT compiler to optimize it, is a good choice. Explain that the `CodeRange` is where the compiled machine code for this function will reside. Emphasize that this is an internal V8 mechanism, not directly accessible to JavaScript developers. Explain the concept of builtins and give examples like `console.log`.

8. **Review and Refine:** Read through the summary and example to ensure accuracy, clarity, and completeness. Check for any potential misunderstandings or areas that could be explained better. For example, initially, I might have focused too much on the details of memory allocation. Refining the explanation to emphasize the *purpose* of the allocation (storing executable code) makes it more relevant to the JavaScript context. Also, clearly stating that the `CodeRange` is internal and not directly manipulable by JS is important.
这个 C++ 代码文件 `v8/src/heap/code-range.cc` 的主要功能是**管理 V8 引擎中用于存储可执行代码的内存区域 (Code Range) 的分配、释放和属性设置**。  它负责确保 V8 能够有效地管理存放 JIT (Just-In-Time) 编译生成的代码以及 V8 内置函数 (builtins) 的内存空间。

以下是该文件功能的详细归纳：

1. **代码区域的分配和释放:**
   - 提供了分配一块连续内存区域用于存放可执行代码的功能。
   - 提供了释放已分配的代码区域的功能。
   - 维护了一个最近释放的代码区域的列表，以便在后续分配时可以尝试重用，提高内存利用率。

2. **代码区域的属性设置:**
   - 可以设置代码区域的内存保护属性，例如设置为只读可执行 (`ReadExecute`) 或读写可执行 (`ReadWriteExecute`)。这对于安全性和防止代码被意外修改至关重要。
   - 在分配时，可以根据需要预留一定的可写区域（特别是在 Windows 上），用于存放一些元数据或执行一些初始化操作。

3. **代码区域分配的优化 (Address Hinting):**
   - 实现了代码区域地址提示机制。它会尝试在靠近 V8 内置函数 (builtins) 的内存区域分配新的代码区域。
   - 这样做的目的是为了利用 CPU 的指令缓存，提高性能，因为 JIT 生成的代码经常需要调用内置函数。靠近的内存地址可以提高调用效率。
   - 它会考虑最近释放的区域，以及预定义的偏好区域 (preferred region)，以找到最佳的分配位置。

4. **处理内置函数 (Builtins):**
   - 提供了重新映射内置函数的功能 (`RemapEmbeddedBuiltins`)。在某些情况下，V8 可能会将内置函数的代码复制到代码区域中，以便更好地与 JIT 生成的代码协同工作。
   - 该功能会考虑内存权限和缓存一致性等问题。

5. **与外部代码空间集成:**
   - 考虑了外部代码空间 (External Code Space) 的情况，在这种情况下，代码区域的分配可能需要满足一些额外的约束，例如避免跨越 4GB 边界。

6. **与内存密封 (Memory Sealing) 集成:**
   -  在启用了内存密封的情况下，可以对代码区域进行密封，进一步提高安全性。

**与 JavaScript 的关系以及 JavaScript 示例:**

`code-range.cc` 的功能是 V8 引擎内部实现的一部分，JavaScript 开发者通常不会直接与其交互。然而，它的存在对于 JavaScript 代码的执行效率至关重要。

当 JavaScript 代码被执行时，V8 的 JIT 编译器 (TurboFan, Crankshaft 等) 会将 JavaScript 代码编译成机器码。这些机器码就需要存储在 `code-range.cc` 管理的代码区域中。

**JavaScript 示例 (说明概念):**

```javascript
function add(a, b) {
  return a + b;
}

// 首次调用，可能由解释器执行
console.log(add(1, 2));

// 多次调用后，JIT 编译器可能会介入，将 add 函数编译成优化的机器码
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}

// 再次调用，执行的是 JIT 编译后的机器码
console.log(add(5, 10));

// 内置函数的例子
console.log("Hello, world!"); // console.log 是一个内置函数
```

**解释:**

1. 当 `add(1, 2)` 第一次被调用时，V8 可能会选择解释执行。
2. 当 `add` 函数在循环中被多次调用后，V8 的 JIT 编译器可能会判断这是一个“热点”函数，并将其编译成优化的机器码。
3. 这些编译后的机器码会被存储在 `code-range.cc` 管理的代码区域中。
4. 之后对 `add(5, 10)` 的调用将直接执行存储在代码区域中的优化后的机器码，而不是重新解释执行，从而提高了性能。
5. `console.log("Hello, world!")` 调用的是 V8 的内置函数。这些内置函数的代码也存储在 `code-range.cc` 管理的内存区域中。

**总结:**

`code-range.cc` 是 V8 引擎中负责管理可执行代码内存的关键组件。它通过提供分配、释放、属性设置和地址提示等功能，确保 V8 能够高效且安全地执行 JavaScript 代码。虽然 JavaScript 开发者无法直接操作它，但它的存在和优化直接影响着 JavaScript 代码的运行速度和性能。 内置函数作为 JavaScript 语言的基础组成部分，也依赖于 `code-range.cc` 提供的内存管理。

Prompt: 
```
这是目录为v8/src/heap/code-range.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/code-range.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <utility>

#include "src/base/bits.h"
#include "src/base/lazy-instance.h"
#include "src/base/once.h"
#include "src/codegen/constants-arch.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/heap/heap-inl.h"
#include "src/utils/allocation.h"
#if defined(V8_OS_WIN64)
#include "src/diagnostics/unwinding-info-win64.h"
#endif  // V8_OS_WIN64

namespace v8 {
namespace internal {

namespace {

DEFINE_LAZY_LEAKY_OBJECT_GETTER(CodeRangeAddressHint, GetCodeRangeAddressHint)

void FunctionInStaticBinaryForAddressHint() {}

}  // anonymous namespace

Address CodeRangeAddressHint::GetAddressHint(size_t code_range_size,
                                             size_t alignment) {
  base::MutexGuard guard(&mutex_);

  // Try to allocate code range in the preferred region where we can use
  // short instructions for calling/jumping to embedded builtins.
  base::AddressRegion preferred_region = Isolate::GetShortBuiltinsCallRegion();

  Address result = 0;
  auto it = recently_freed_.find(code_range_size);
  // No recently freed region has been found, try to provide a hint for placing
  // a code region.
  if (it == recently_freed_.end() || it->second.empty()) {
    if (V8_ENABLE_NEAR_CODE_RANGE_BOOL && !preferred_region.is_empty()) {
      const auto memory_ranges = base::OS::GetFirstFreeMemoryRangeWithin(
          preferred_region.begin(), preferred_region.end(), code_range_size,
          alignment);
      if (memory_ranges.has_value()) {
        result = memory_ranges.value().start;
        CHECK(IsAligned(result, alignment));
        return result;
      }
      // The empty memory_ranges means that GetFirstFreeMemoryRangeWithin() API
      // is not supported, so use the lowest address from the preferred region
      // as a hint because it'll be at least as good as the fallback hint but
      // with a higher chances to point to the free address space range.
      return RoundUp(preferred_region.begin(), alignment);
    }
    return RoundUp(FUNCTION_ADDR(&FunctionInStaticBinaryForAddressHint),
                   alignment);
  }

  // Try to reuse near code range first.
  if (V8_ENABLE_NEAR_CODE_RANGE_BOOL && !preferred_region.is_empty()) {
    auto freed_regions_for_size = it->second;
    for (auto it_freed = freed_regions_for_size.rbegin();
         it_freed != freed_regions_for_size.rend(); ++it_freed) {
      Address code_range_start = *it_freed;
      if (preferred_region.contains(code_range_start, code_range_size)) {
        CHECK(IsAligned(code_range_start, alignment));
        freed_regions_for_size.erase((it_freed + 1).base());
        return code_range_start;
      }
    }
  }

  result = it->second.back();
  CHECK(IsAligned(result, alignment));
  it->second.pop_back();
  return result;
}

void CodeRangeAddressHint::NotifyFreedCodeRange(Address code_range_start,
                                                size_t code_range_size) {
  base::MutexGuard guard(&mutex_);
  recently_freed_[code_range_size].push_back(code_range_start);
}

CodeRange::~CodeRange() { Free(); }

// static
size_t CodeRange::GetWritableReservedAreaSize() {
  return kReservedCodeRangePages * MemoryAllocator::GetCommitPageSize();
}

#define TRACE(...) \
  if (v8_flags.trace_code_range_allocation) PrintF(__VA_ARGS__)

bool CodeRange::InitReservation(v8::PageAllocator* page_allocator,
                                size_t requested, bool immutable) {
  DCHECK_NE(requested, 0);
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    page_allocator = GetPlatformPageAllocator();
  }

  if (requested <= kMinimumCodeRangeSize) {
    requested = kMinimumCodeRangeSize;
  }

  const size_t kPageSize = MutablePageMetadata::kPageSize;
  CHECK(IsAligned(kPageSize, page_allocator->AllocatePageSize()));

  // When V8_EXTERNAL_CODE_SPACE_BOOL is enabled the allocatable region must
  // not cross the 4Gb boundary and thus the default compression scheme of
  // truncating the InstructionStream pointers to 32-bits still works. It's
  // achieved by specifying base_alignment parameter.
  const size_t base_alignment = V8_EXTERNAL_CODE_SPACE_BOOL
                                    ? base::bits::RoundUpToPowerOfTwo(requested)
                                    : kPageSize;

  DCHECK_IMPLIES(kPlatformRequiresCodeRange,
                 requested <= kMaximalCodeRangeSize);

  VirtualMemoryCage::ReservationParams params;
  params.page_allocator = page_allocator;
  params.reservation_size = requested;
  params.page_size = kPageSize;
  if (v8_flags.jitless) {
    params.permissions = PageAllocator::Permission::kNoAccess;
    params.page_initialization_mode =
        base::PageInitializationMode::kAllocatedPagesCanBeUninitialized;
    params.page_freeing_mode = base::PageFreeingMode::kMakeInaccessible;
  } else {
    params.permissions = PageAllocator::Permission::kNoAccessWillJitLater;
    params.page_initialization_mode =
        base::PageInitializationMode::kRecommitOnly;
    params.page_freeing_mode = base::PageFreeingMode::kDiscard;
  }

  const size_t allocate_page_size = page_allocator->AllocatePageSize();
  constexpr size_t kRadiusInMB =
      kMaxPCRelativeCodeRangeInMB > 1024 ? kMaxPCRelativeCodeRangeInMB : 4096;
  auto preferred_region = GetPreferredRegion(kRadiusInMB, kPageSize);

  TRACE("=== Preferred region: [%p, %p)\n",
        reinterpret_cast<void*>(preferred_region.begin()),
        reinterpret_cast<void*>(preferred_region.end()));

  // For configurations with enabled pointer compression and shared external
  // code range we can afford trying harder to allocate code range near .text
  // section.
  const bool kShouldTryHarder = V8_EXTERNAL_CODE_SPACE_BOOL &&
                                COMPRESS_POINTERS_IN_SHARED_CAGE_BOOL &&
                                v8_flags.better_code_range_allocation;

  if (kShouldTryHarder) {
    // Relax alignment requirement while trying to allocate code range inside
    // preferred region.
    params.base_alignment = kPageSize;

    // TODO(v8:11880): consider using base::OS::GetFirstFreeMemoryRangeWithin()
    // to avoid attempts that's going to fail anyway.

    VirtualMemoryCage candidate_cage;

    // Try to allocate code range at the end of preferred region, by going
    // towards the start in steps.
    const int kAllocationTries = 16;
    params.requested_start_hint =
        RoundDown(preferred_region.end() - requested, kPageSize);
    Address step =
        RoundDown(preferred_region.size() / kAllocationTries, kPageSize);
    for (int i = 0; i < kAllocationTries; i++) {
      TRACE("=== Attempt #%d, hint=%p\n", i,
            reinterpret_cast<void*>(params.requested_start_hint));
      if (candidate_cage.InitReservation(params)) {
        TRACE("=== Attempt #%d (%p): [%p, %p)\n", i,
              reinterpret_cast<void*>(params.requested_start_hint),
              reinterpret_cast<void*>(candidate_cage.region().begin()),
              reinterpret_cast<void*>(candidate_cage.region().end()));
        // Allocation succeeded, check if it's in the preferred range.
        if (preferred_region.contains(candidate_cage.region())) break;
        // This allocation is not the one we are searhing for.
        candidate_cage.Free();
      }
      if (step == 0) break;
      params.requested_start_hint -= step;
    }
    if (candidate_cage.IsReserved()) {
      *static_cast<VirtualMemoryCage*>(this) = std::move(candidate_cage);
    }
  }
  if (!IsReserved()) {
    // TODO(v8:11880): Use base_alignment here once ChromeOS issue is fixed.
    Address the_hint = GetCodeRangeAddressHint()->GetAddressHint(
        requested, allocate_page_size);
    the_hint = RoundDown(the_hint, base_alignment);
    // Last resort, use whatever region we get.
    params.base_alignment = base_alignment;
    params.requested_start_hint = the_hint;
    if (!VirtualMemoryCage::InitReservation(params)) {
      params.requested_start_hint = kNullAddress;
      if (!VirtualMemoryCage::InitReservation(params)) return false;
    }
    TRACE("=== Fallback attempt, hint=%p: [%p, %p)\n",
          reinterpret_cast<void*>(params.requested_start_hint),
          reinterpret_cast<void*>(region().begin()),
          reinterpret_cast<void*>(region().end()));
  }

  if (v8_flags.abort_on_far_code_range &&
      !preferred_region.contains(region())) {
    // We didn't manage to allocate the code range close enough.
    FATAL("Failed to allocate code range close to the .text section");
  }

  // On some platforms, specifically Win64, we need to reserve some pages at
  // the beginning of an executable space. See
  //   https://cs.chromium.org/chromium/src/components/crash/content/
  //     app/crashpad_win.cc?rcl=fd680447881449fba2edcf0589320e7253719212&l=204
  // for details.
  const size_t reserved_area = GetWritableReservedAreaSize();
  if (reserved_area > 0) {
    CHECK_LE(reserved_area, kPageSize);
    // Exclude the reserved area from further allocations.
    CHECK(page_allocator_->AllocatePagesAt(base(), kPageSize,
                                           PageAllocator::kNoAccess));
    // Commit required amount of writable memory.
    if (!reservation()->SetPermissions(base(), reserved_area,
                                       PageAllocator::kReadWrite)) {
      return false;
    }
#if defined(V8_OS_WIN64)
    if (win64_unwindinfo::CanRegisterUnwindInfoForNonABICompliantCodeRange()) {
      win64_unwindinfo::RegisterNonABICompliantCodeRange(
          reinterpret_cast<void*>(base()), size());
    }
#endif  // V8_OS_WIN64
  }

// Don't pre-commit the code cage on Windows since it uses memory and it's not
// required for recommit.
#if !defined(V8_OS_WIN)
  if (params.page_initialization_mode ==
      base::PageInitializationMode::kRecommitOnly) {
    void* base =
        reinterpret_cast<void*>(page_allocator_->begin() + reserved_area);
    size_t size = page_allocator_->size() - reserved_area;
    if (ThreadIsolation::Enabled()) {
      if (!ThreadIsolation::MakeExecutable(reinterpret_cast<Address>(base),
                                           size)) {
        return false;
      }
    } else if (!params.page_allocator->SetPermissions(
                   base, size, PageAllocator::kReadWriteExecute)) {
      return false;
    }
    if (immutable) {
#ifdef DEBUG
      immutable_ = true;
#endif
#ifdef V8_ENABLE_MEMORY_SEALING
      params.page_allocator->SealPages(base, size);
#endif
    }
    DiscardSealedMemoryScope discard_scope("Discard global code range.");
    if (!params.page_allocator->DiscardSystemPages(base, size)) return false;
  }
#endif  // !defined(V8_OS_WIN)

  return true;
}

// Preferred region for the code range is an intersection of the following
// regions:
// a) [builtins - kMaxPCRelativeDistance, builtins + kMaxPCRelativeDistance)
// b) [RoundDown(builtins, 4GB), RoundUp(builtins, 4GB)) in order to ensure
// Requirement (a) is there to avoid remaping of embedded builtins into
// the code for architectures where PC-relative jump/call distance is big
// enough.
// Requirement (b) is aiming at helping CPU branch predictors in general and
// in case V8_EXTERNAL_CODE_SPACE is enabled it ensures that
// ExternalCodeCompressionScheme works for all pointers in the code range.
// static
base::AddressRegion CodeRange::GetPreferredRegion(size_t radius_in_megabytes,
                                                  size_t allocate_page_size) {
#ifdef V8_TARGET_ARCH_64_BIT
  // Compute builtins location.
  Address embedded_blob_code_start =
      reinterpret_cast<Address>(Isolate::CurrentEmbeddedBlobCode());
  Address embedded_blob_code_end;
  if (embedded_blob_code_start == kNullAddress) {
    // When there's no embedded blob use address of a function from the binary
    // as an approximation.
    embedded_blob_code_start =
        FUNCTION_ADDR(&FunctionInStaticBinaryForAddressHint);
    embedded_blob_code_end = embedded_blob_code_start + 1;
  } else {
    embedded_blob_code_end =
        embedded_blob_code_start + Isolate::CurrentEmbeddedBlobCodeSize();
  }

  // Fulfil requirement (a).
  constexpr size_t max_size = std::numeric_limits<size_t>::max();
  size_t radius = radius_in_megabytes * MB;

  Address region_start =
      RoundUp(embedded_blob_code_end - radius, allocate_page_size);
  if (region_start > embedded_blob_code_end) {
    // |region_start| underflowed.
    region_start = 0;
  }
  Address region_end =
      RoundDown(embedded_blob_code_start + radius, allocate_page_size);
  if (region_end < embedded_blob_code_start) {
    // |region_end| overflowed.
    region_end = RoundDown(max_size, allocate_page_size);
  }

  // Fulfil requirement (b).
  constexpr size_t k4GB = size_t{4} * GB;
  Address four_gb_cage_start = RoundDown(embedded_blob_code_start, k4GB);
  Address four_gb_cage_end = four_gb_cage_start + k4GB;

  region_start = std::max(region_start, four_gb_cage_start);
  region_end = std::min(region_end, four_gb_cage_end);

#ifdef V8_EXTERNAL_CODE_SPACE
  // If ExternalCodeCompressionScheme ever changes then the requirements might
  // need to be updated.
  static_assert(k4GB <= kPtrComprCageReservationSize);
  DCHECK_EQ(four_gb_cage_start,
            ExternalCodeCompressionScheme::PrepareCageBaseAddress(
                embedded_blob_code_start));
#endif  // V8_EXTERNAL_CODE_SPACE

  return base::AddressRegion(region_start, region_end - region_start);
#else
  return {};
#endif  // V8_TARGET_ARCH_64_BIT
}

void CodeRange::Free() {
  // TODO(361480580): this DCHECK is temporarily disabled since we free the
  // global CodeRange in the PoolTest.
  // DCHECK(!immutable_);

  if (IsReserved()) {
#if defined(V8_OS_WIN64)
    if (win64_unwindinfo::CanRegisterUnwindInfoForNonABICompliantCodeRange()) {
      win64_unwindinfo::UnregisterNonABICompliantCodeRange(
          reinterpret_cast<void*>(base()));
    }
#endif  // V8_OS_WIN64
    GetCodeRangeAddressHint()->NotifyFreedCodeRange(
        reservation()->region().begin(), reservation()->region().size());
    VirtualMemoryCage::Free();
  }
}

uint8_t* CodeRange::RemapEmbeddedBuiltins(Isolate* isolate,
                                          const uint8_t* embedded_blob_code,
                                          size_t embedded_blob_code_size) {
  base::MutexGuard guard(&remap_embedded_builtins_mutex_);

  // Remap embedded builtins into the end of the address range controlled by
  // the BoundedPageAllocator.
  const base::AddressRegion code_region(page_allocator()->begin(),
                                        page_allocator()->size());
  CHECK_NE(code_region.begin(), kNullAddress);
  CHECK(!code_region.is_empty());

  uint8_t* embedded_blob_code_copy =
      embedded_blob_code_copy_.load(std::memory_order_acquire);
  if (embedded_blob_code_copy) {
    DCHECK(
        code_region.contains(reinterpret_cast<Address>(embedded_blob_code_copy),
                             embedded_blob_code_size));
    SLOW_DCHECK(memcmp(embedded_blob_code, embedded_blob_code_copy,
                       embedded_blob_code_size) == 0);
    return embedded_blob_code_copy;
  }

  const size_t kAllocatePageSize = page_allocator()->AllocatePageSize();
  const size_t kCommitPageSize = page_allocator()->CommitPageSize();
  size_t allocate_code_size =
      RoundUp(embedded_blob_code_size, kAllocatePageSize);

  // Allocate the re-embedded code blob in such a way that it will be reachable
  // by PC-relative addressing from biggest possible region.
  const size_t max_pc_relative_code_range = kMaxPCRelativeCodeRangeInMB * MB;
  size_t hint_offset =
      std::min(max_pc_relative_code_range, code_region.size()) -
      allocate_code_size;
  void* hint = reinterpret_cast<void*>(code_region.begin() + hint_offset);

  embedded_blob_code_copy =
      reinterpret_cast<uint8_t*>(page_allocator()->AllocatePages(
          hint, allocate_code_size, kAllocatePageSize,
          PageAllocator::kNoAccessWillJitLater));

  if (!embedded_blob_code_copy) {
    V8::FatalProcessOutOfMemory(
        isolate, "Can't allocate space for re-embedded builtins");
  }
  CHECK_EQ(embedded_blob_code_copy, hint);

  if (code_region.size() > max_pc_relative_code_range) {
    // The re-embedded code blob might not be reachable from the end part of
    // the code range, so ensure that code pages will never be allocated in
    // the "unreachable" area.
    Address unreachable_start =
        reinterpret_cast<Address>(embedded_blob_code_copy) +
        max_pc_relative_code_range;

    if (code_region.contains(unreachable_start)) {
      size_t unreachable_size = code_region.end() - unreachable_start;

      void* result = page_allocator()->AllocatePages(
          reinterpret_cast<void*>(unreachable_start), unreachable_size,
          kAllocatePageSize, PageAllocator::kNoAccess);
      CHECK_EQ(reinterpret_cast<Address>(result), unreachable_start);
    }
  }

  size_t code_size = RoundUp(embedded_blob_code_size, kCommitPageSize);
  if constexpr (base::OS::IsRemapPageSupported()) {
    // By default, the embedded builtins are not remapped, but copied. This
    // costs memory, since builtins become private dirty anonymous memory,
    // rather than shared, clean, file-backed memory for the embedded version.
    // If the OS supports it, we can remap the builtins *on top* of the space
    // allocated in the code range, making the "copy" shared, clean, file-backed
    // memory, and thus saving sizeof(builtins).
    //
    // Builtins should start at a page boundary, see
    // platform-embedded-file-writer-mac.cc. If it's not the case (e.g. if the
    // embedded builtins are not coming from the binary), fall back to copying.
    if (IsAligned(reinterpret_cast<uintptr_t>(embedded_blob_code),
                  kCommitPageSize)) {
      bool ok = base::OS::RemapPages(embedded_blob_code, code_size,
                                     embedded_blob_code_copy,
                                     base::OS::MemoryPermission::kReadExecute);

      if (ok) {
        embedded_blob_code_copy_.store(embedded_blob_code_copy,
                                       std::memory_order_release);
        return embedded_blob_code_copy;
      }
    }
  }

  if (V8_HEAP_USE_PTHREAD_JIT_WRITE_PROTECT ||
      V8_HEAP_USE_BECORE_JIT_WRITE_PROTECT || ThreadIsolation::Enabled()) {
    if (!page_allocator()->RecommitPages(embedded_blob_code_copy, code_size,
                                         PageAllocator::kReadWriteExecute)) {
      V8::FatalProcessOutOfMemory(isolate,
                                  "Re-embedded builtins: recommit pages");
    }
    RwxMemoryWriteScope rwx_write_scope(
        "Enable write access to copy the blob code into the code range");
    memcpy(embedded_blob_code_copy, embedded_blob_code,
           embedded_blob_code_size);
  } else {
    if (!page_allocator()->SetPermissions(embedded_blob_code_copy, code_size,
                                          PageAllocator::kReadWrite)) {
      V8::FatalProcessOutOfMemory(isolate,
                                  "Re-embedded builtins: set permissions");
    }
    memcpy(embedded_blob_code_copy, embedded_blob_code,
           embedded_blob_code_size);

    if (!page_allocator()->SetPermissions(embedded_blob_code_copy, code_size,
                                          PageAllocator::kReadExecute)) {
      V8::FatalProcessOutOfMemory(isolate,
                                  "Re-embedded builtins: set permissions");
    }
  }
  embedded_blob_code_copy_.store(embedded_blob_code_copy,
                                 std::memory_order_release);
  return embedded_blob_code_copy;
}

}  // namespace internal
}  // namespace v8

"""

```