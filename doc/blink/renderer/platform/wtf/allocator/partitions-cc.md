Response:
Let's break down the thought process for analyzing this `partitions.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to JavaScript/HTML/CSS, any logic/reasoning with input/output, and common usage errors.

2. **Initial Scan for Keywords and Structure:**  Quickly read through the code, looking for key terms related to memory management: `alloc`, `free`, `partition`, `root`, `buffer`, `array_buffer`, `malloc`, `OOM`, `Initialize`. Notice the namespace `WTF` and the file path `blink/renderer/platform/wtf`. This immediately suggests it's a low-level utility within the Blink rendering engine dealing with memory allocation.

3. **Identify Core Components:**  The code clearly defines and initializes different memory partitions: `fast_malloc_root_`, `array_buffer_root_`, and `buffer_root_`. These are likely distinct memory pools for different types of data.

4. **Focus on Functionality of `Partitions` Class:**  The `Partitions` class seems to be a central point for managing these memory partitions. Examine its methods:
    * `Initialize()`/`InitializeOnce()`: Sets up the memory partitions.
    * `InitializeArrayBufferPartition()`:  Specific initialization for array buffers.
    * `BufferMalloc()`, `BufferFree()`, `BufferTryRealloc()`: Allocation functions for the `buffer_root_` partition.
    * `FastMalloc()`, `FastFree()`, `FastZeroedMalloc()`: Allocation functions potentially related to faster or general-purpose allocation (and note the conditional handling based on `USE_PARTITION_ALLOC_AS_MALLOC`).
    * `HandleOutOfMemory()`: Deals with out-of-memory situations. This is critical.
    * `DumpMemoryStats()`: Provides debugging/monitoring information.
    * `TotalSizeOfCommittedPages()`, `TotalActiveBytes()`:  Metrics about memory usage.
    * `AdjustPartitionsForForeground()`, `AdjustPartitionsForBackground()`: Hints at performance optimization based on browser state.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** This requires some domain knowledge about how a browser rendering engine works.
    * **JavaScript:**  `ArrayBuffer` is a JavaScript object for raw binary data. The presence of `InitializeArrayBufferPartition()` strongly suggests a connection. JavaScript also needs memory for objects and data structures, which could potentially use the `fast_malloc_root_` or `buffer_root_`.
    * **HTML:**  The DOM (Document Object Model) is a tree-like representation of the HTML structure. DOM nodes and their associated data need memory allocation. The `buffer_root_` or `fast_malloc_root_` could be used here.
    * **CSS:** CSS properties and styles applied to DOM elements also require memory. Again,  `buffer_root_` or `fast_malloc_root_` are potential candidates.

6. **Reasoning and Input/Output Examples:** Think about how these memory partitions are *used*.
    * **ArrayBuffer:**  If JavaScript creates an `ArrayBuffer`, the `InitializeArrayBufferPartition()` is likely involved, and `BufferMalloc` or a similar low-level allocation within that partition would be used to reserve the memory. *Hypothetical input:* JavaScript code `new ArrayBuffer(1024)`. *Hypothetical output:* 1024 bytes allocated from the `array_buffer_root_`.
    * **DOM Node:** When the browser parses HTML and creates a DOM element (e.g., a `<div>`), memory is needed for the node object itself and its properties. *Hypothetical input:* HTML `<div>Hello</div>`. *Hypothetical output:*  Allocation of memory for the `div` node structure, potentially from `buffer_root_`.

7. **Identify Potential Usage Errors:** Look for areas where incorrect usage could lead to problems.
    * **Memory Leaks:**  If memory is allocated with `BufferMalloc` or `FastMalloc` but not subsequently freed with `BufferFree` or `FastFree`, it's a memory leak.
    * **Double Free:** Calling `BufferFree` or `FastFree` on the same memory address twice will likely cause a crash or corruption.
    * **Use After Free:** Accessing memory after it has been freed is a classic and dangerous error.
    * **Incorrect Size Calculation:**  Providing the wrong size to `BufferMalloc` could lead to buffer overflows or underflows.

8. **Analyze Feature Flags:** Notice the `BASE_FEATURE` macros (e.g., `kBlinkUseLargeEmptySlotSpanRingForBufferRoot`) and the use of `base::FeatureList::IsEnabled()`. This indicates that some behavior is controlled by runtime configuration. Mention these and their potential impact.

9. **Consider Out-of-Memory Handling:**  The `HandleOutOfMemory()` function is crucial. Note that it logs information and then crashes the process. This is a deliberate strategy in browsers to prevent further unpredictable behavior.

10. **Refine and Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logic/Reasoning, and Usage Errors. Use clear and concise language. Provide specific code examples where applicable (even if they are simplified).

11. **Review and Iterate:** Read through the generated answer, checking for accuracy and completeness. Ensure that the examples make sense and that the explanations are easy to understand. For instance, initially, I might have just said "allocates memory," but refining it to "manages different memory partitions for various purposes within the rendering engine" is more informative.

This systematic approach, combining code analysis with domain knowledge, helps to thoroughly understand the purpose and implications of the given source code.
这个文件 `blink/renderer/platform/wtf/allocator/partitions.cc` 的主要功能是**管理 Blink 渲染引擎中不同类型的内存分区 (memory partitions)**。它使用了 Chromium 的 `PartitionAlloc` 库来实现高效且安全的内存分配。

以下是更详细的功能列表：

**核心功能:**

1. **定义和管理多个内存分区:**  该文件定义了至少三个主要的内存分区：
   - `fast_malloc_root_`: 用于通用的小型对象的快速分配。
   - `array_buffer_root_`: 专门用于 JavaScript 的 `ArrayBuffer` 对象的分配。这个分区有特定的对齐要求 (16 字节对齐)。
   - `buffer_root_`: 用于分配其他类型的缓冲区，例如 DOM 节点、CSS 样式等。

2. **初始化内存分区:**  `Initialize()` 和 `InitializeArrayBufferPartition()` 函数负责初始化这些内存分区，包括设置分区选项（例如是否启用备份引用指针、内存标签等）。

3. **提供内存分配和释放的接口:**  它提供了用于在不同分区中分配和释放内存的静态方法，例如：
   - `BufferMalloc()`, `BufferFree()`, `BufferTryRealloc()` 用于 `buffer_root_` 分区。
   - `FastMalloc()`, `FastFree()`, `FastZeroedMalloc()` 用于 `fast_malloc_root_` 分区。

4. **处理内存不足 (Out-of-Memory) 情况:**  `HandleOutOfMemory()` 函数在内存分配失败时被调用。它会记录内存使用情况，并触发崩溃报告以帮助开发者诊断问题。该函数会根据不同的内存使用量输出不同的崩溃签名。

5. **提供内存统计信息:**  `DumpMemoryStats()` 函数用于输出各个内存分区的统计信息，例如已分配的字节数。 `TotalSizeOfCommittedPages()` 和 `TotalActiveBytes()` 提供聚合的内存使用情况。

6. **根据前后台状态调整内存使用:** `AdjustPartitionsForForeground()` 和 `AdjustPartitionsForBackground()` 函数允许在浏览器切换到前台或后台时调整内存分区的行为，例如减少后台时的内存占用。

7. **集成 `PartitionAlloc` 特性:** 文件中使用了 `PartitionAlloc` 的各种特性，例如线程缓存、备份引用指针、内存标签、小单槽 span 等，这些特性可以通过 feature flags 进行配置。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接参与了 Blink 渲染引擎为 JavaScript、HTML 和 CSS 分配内存的过程。

**JavaScript:**

* **`ArrayBuffer`:**  `array_buffer_root_` 分区专门用于分配 JavaScript 的 `ArrayBuffer` 对象。当 JavaScript 代码创建一个 `ArrayBuffer` 时，Blink 会从这个分区分配内存。
   * **假设输入 (JavaScript):** `let buffer = new ArrayBuffer(1024);`
   * **逻辑推理:**  Blink 的 JavaScript 引擎 (V8) 会调用 Blink 提供的内存分配接口，最终调用 `Partitions::BufferMalloc` 或类似的函数，从 `array_buffer_root_` 分区中分配 1024 字节的内存。
   * **举例说明:**  `ArrayBuffer` 用于存储二进制数据，例如在 Canvas 绘图、WebGL 或处理网络数据时。

* **其他 JavaScript 对象:**  `fast_malloc_root_` 或 `buffer_root_` 分区可能用于分配其他 JavaScript 对象（例如普通对象、数组等）。虽然 `array_buffer_root_` 专门用于 `ArrayBuffer`，但其他的堆分配需求可能使用其他分区。

**HTML:**

* **DOM 节点:**  当浏览器解析 HTML 文档并构建 DOM 树时，需要为每个 DOM 节点（例如 `<div>`, `<p>`, `<span>` 等）分配内存。 这些内存分配很可能使用 `buffer_root_` 分区。
   * **假设输入 (HTML):** `<div>Hello World</div>`
   * **逻辑推理:**  Blink 的 HTML 解析器会创建表示 `div` 元素的 DOM 节点对象，并分配内存来存储该节点的属性和子节点等信息。这个分配可能通过 `Partitions::BufferMalloc` 进行。
   * **举例说明:**  每个 HTML 标签在内存中都有一个对应的 DOM 节点对象。

**CSS:**

* **CSS 样式:**  当浏览器解析 CSS 规则并将其应用于 DOM 节点时，需要分配内存来存储这些样式信息。 这些样式信息，例如颜色、字体大小、布局属性等，可能会存储在 `buffer_root_` 分区中。
   * **假设输入 (CSS):** `.my-class { color: red; font-size: 16px; }`
   * **逻辑推理:**  当这个 CSS 规则应用到一个 DOM 元素时，Blink 会分配内存来存储该元素的样式信息，包括 `color` 和 `font-size` 属性的值。
   * **举例说明:**  浏览器需要存储每个元素的样式信息以进行渲染。

**用户或编程常见的错误举例:**

1. **内存泄漏 (Memory Leak):**
   - **场景:**  在 Blink 的代码中，如果使用 `Partitions::BufferMalloc` 或 `Partitions::FastMalloc` 分配了内存，但在不再使用时忘记调用 `Partitions::BufferFree` 或 `Partitions::FastFree` 进行释放，就会导致内存泄漏。
   - **假设输入:** 一个不断创建新 DOM 节点或 `ArrayBuffer` 但不释放它们的逻辑。
   - **输出:** 随着时间的推移，浏览器进程的内存占用会不断增加，最终可能导致性能下降甚至崩溃。

2. **重复释放内存 (Double Free):**
   - **场景:**  如果对同一个内存地址多次调用 `Partitions::BufferFree` 或 `Partitions::FastFree`，会导致内存管理器内部状态混乱。
   - **假设输入:**  代码中存在错误的逻辑，导致同一块内存被释放了两次。
   - **输出:** 很可能导致程序崩溃，因为内存管理器可能会尝试操作已被标记为释放的内存。

3. **使用已释放的内存 (Use-After-Free):**
   - **场景:**  在调用 `Partitions::BufferFree` 或 `Partitions::FastFree` 释放内存后，仍然尝试访问该内存地址的数据。
   - **假设输入:**  一个对象被释放后，代码中仍然持有指向该对象内存的指针并尝试解引用。
   - **输出:**  会导致未定义的行为，可能读取到垃圾数据，或者导致程序崩溃。

4. **错误的内存大小计算:**
   - **场景:**  在使用 `Partitions::BufferMalloc` 或 `Partitions::FastMalloc` 分配内存时，传递了错误的大小参数，例如分配的空间不足以存储需要存储的数据。
   - **假设输入:** 需要存储一个长度为 N 的字符串，但分配的内存大小小于 N+1（需要包含 null 终止符）。
   - **输出:**  可能导致缓冲区溢出，覆盖相邻的内存区域，从而引发各种问题，包括程序崩溃或安全漏洞。

**逻辑推理的假设输入与输出示例:**

* **假设输入:**  调用 `Partitions::BufferMalloc(100, "MyObject")`
* **逻辑推理:**  Blink 的内存分配器会在 `buffer_root_` 分区中找到一个足够容纳 100 字节的空闲块，并标记为已分配。分配的内存块会与 "MyObject" 这个类型名称关联，用于调试和统计。
* **输出:**  返回一个指向新分配的 100 字节内存块的指针。

* **假设输入:**  JavaScript 代码执行 `new Uint8Array(50);`
* **逻辑推理:**  JavaScript 引擎会创建一个 `Uint8Array` 对象，并在底层需要分配 50 字节的内存来存储数组的元素。由于 `Uint8Array` 是类型化数组，其底层实现通常是 `ArrayBuffer`。因此，Blink 会尝试从 `array_buffer_root_` 分区分配内存。
* **输出:**  在 `array_buffer_root_` 分区中分配 50 字节的内存，并将其关联到新创建的 `Uint8Array` 对象。

总而言之，`partitions.cc` 文件在 Blink 渲染引擎中扮演着至关重要的角色，它负责管理不同用途的内存分配，直接影响着 JavaScript 对象的创建、DOM 树的构建和 CSS 样式的存储，是保证浏览器高效稳定运行的基础组件之一。

### 提示词
```
这是目录为blink/renderer/platform/wtf/allocator/partitions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"

#include "base/allocator/partition_alloc_features.h"
#include "base/allocator/partition_alloc_support.h"
#include "base/debug/alias.h"
#include "base/feature_list.h"
#include "base/no_destructor.h"
#include "base/strings/safe_sprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/thread_annotations.h"
#include "build/build_config.h"
#include "components/crash/core/common/crash_key.h"
#include "partition_alloc/buildflags.h"
#include "partition_alloc/oom.h"
#include "partition_alloc/page_allocator.h"
#include "partition_alloc/partition_alloc.h"
#include "partition_alloc/partition_alloc_constants.h"
#include "partition_alloc/partition_root.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace WTF {

const char* const Partitions::kAllocatedObjectPoolName =
    "partition_alloc/allocated_objects";

BASE_FEATURE(kBlinkUseLargeEmptySlotSpanRingForBufferRoot,
             "BlinkUseLargeEmptySlotSpanRingForBufferRoot",
#if BUILDFLAG(IS_MAC)
             base::FEATURE_ENABLED_BY_DEFAULT);
#else
             base::FEATURE_DISABLED_BY_DEFAULT);
#endif

bool Partitions::initialized_ = false;

// These statics are inlined, so cannot be LazyInstances. We create the values,
// and then set the pointers correctly in Initialize().
partition_alloc::PartitionRoot* Partitions::fast_malloc_root_ = nullptr;
partition_alloc::PartitionRoot* Partitions::array_buffer_root_ = nullptr;
partition_alloc::PartitionRoot* Partitions::buffer_root_ = nullptr;

namespace {

// Reads feature configuration and returns a suitable
// `PartitionOptions`.
partition_alloc::PartitionOptions PartitionOptionsFromFeatures() {
  using base::features::BackupRefPtrEnabledProcesses;
  using base::features::BackupRefPtrMode;
  using partition_alloc::PartitionOptions;

#if PA_BUILDFLAG(ENABLE_BACKUP_REF_PTR_SUPPORT)
  const auto brp_mode = base::features::kBackupRefPtrModeParam.Get();
  const bool process_affected_by_brp_flag =
      base::features::kBackupRefPtrEnabledProcessesParam.Get() ==
          BackupRefPtrEnabledProcesses::kAllProcesses ||
      base::features::kBackupRefPtrEnabledProcessesParam.Get() ==
          BackupRefPtrEnabledProcesses::kBrowserAndRenderer;
  const bool enable_brp = base::FeatureList::IsEnabled(
                              base::features::kPartitionAllocBackupRefPtr) &&
                          (brp_mode == BackupRefPtrMode::kEnabled) &&
                          process_affected_by_brp_flag;
#else  // PA_BUILDFLAG(ENABLE_BACKUP_REF_PTR_SUPPORT)
  const bool enable_brp = false;
#endif

  const auto brp_setting =
      enable_brp ? PartitionOptions::kEnabled : PartitionOptions::kDisabled;

  const bool enable_memory_tagging = base::allocator::PartitionAllocSupport::
      ShouldEnableMemoryTaggingInRendererProcess();
  const auto memory_tagging =
      enable_memory_tagging ? partition_alloc::PartitionOptions::kEnabled
                            : partition_alloc::PartitionOptions::kDisabled;
#if PA_BUILDFLAG(USE_FREELIST_DISPATCHER)
  const bool pool_offset_freelists_enabled =
      base::FeatureList::IsEnabled(base::features::kUsePoolOffsetFreelists);
#else
  const bool pool_offset_freelists_enabled = false;
#endif  // PA_BUILDFLAG(USE_FREELIST_DISPATCHER)
  const auto use_pool_offset_freelists =
      pool_offset_freelists_enabled
          ? partition_alloc::PartitionOptions::kEnabled
          : partition_alloc::PartitionOptions::kDisabled;
  // No need to call ChangeMemoryTaggingModeForAllThreadsPerProcess() as it will
  // be handled in ReconfigureAfterFeatureListInit().
  PartitionOptions opts;
  opts.star_scan_quarantine = PartitionOptions::kAllowed;
  opts.backup_ref_ptr = brp_setting;
  opts.memory_tagging = {.enabled = memory_tagging};
  opts.use_pool_offset_freelists = use_pool_offset_freelists;
  opts.use_small_single_slot_spans =
      base::FeatureList::IsEnabled(
          base::features::kPartitionAllocUseSmallSingleSlotSpans)
          ? partition_alloc::PartitionOptions::kEnabled
          : partition_alloc::PartitionOptions::kDisabled;
  return opts;
}

}  // namespace

// static
void Partitions::Initialize() {
  static bool initialized = InitializeOnce();
  DCHECK(initialized);
}

// static
bool Partitions::InitializeOnce() {
  using partition_alloc::PartitionOptions;

  partition_alloc::PartitionAllocGlobalInit(&Partitions::HandleOutOfMemory);

  auto options = PartitionOptionsFromFeatures();

  const auto actual_brp_setting = options.backup_ref_ptr;
  if (base::FeatureList::IsEnabled(
          base::features::kPartitionAllocDisableBRPInBufferPartition)) {
    options.backup_ref_ptr = PartitionOptions::kDisabled;
  }

  static base::NoDestructor<partition_alloc::PartitionAllocator>
      buffer_allocator(options);
  buffer_root_ = buffer_allocator->root();
  if (base::FeatureList::IsEnabled(
          kBlinkUseLargeEmptySlotSpanRingForBufferRoot)) {
    buffer_root_->EnableLargeEmptySlotSpanRing();
  }

  if (base::FeatureList::IsEnabled(
          base::features::kPartitionAllocDisableBRPInBufferPartition)) {
    options.backup_ref_ptr = actual_brp_setting;
  }

  // FastMalloc doesn't provide isolation, only a (hopefully fast) malloc().
  // When PartitionAlloc is already the malloc() implementation, there is
  // nothing to do.
  //
  // Note that we could keep the two heaps separate, but each PartitionAlloc's
  // root has a cost, both in used memory and in virtual address space. Don't
  // pay it when we don't have to.
#if !PA_BUILDFLAG(USE_PARTITION_ALLOC_AS_MALLOC)
  options.thread_cache = PartitionOptions::kEnabled;
  static base::NoDestructor<partition_alloc::PartitionAllocator>
      fast_malloc_allocator(options);
  fast_malloc_root_ = fast_malloc_allocator->root();
#endif

  initialized_ = true;
  return initialized_;
}

// static
void Partitions::InitializeArrayBufferPartition() {
  CHECK(initialized_);
  CHECK(!ArrayBufferPartitionInitialized());

  // BackupRefPtr disallowed because it will prevent allocations from being 16B
  // aligned as required by ArrayBufferContents.
  static base::NoDestructor<partition_alloc::PartitionAllocator>
      array_buffer_allocator([]() {
        partition_alloc::PartitionOptions opts;
        opts.star_scan_quarantine = partition_alloc::PartitionOptions::kAllowed;
        opts.backup_ref_ptr = partition_alloc::PartitionOptions::kDisabled;
        // When the V8 virtual memory cage is enabled, the ArrayBuffer
        // partition must be placed inside of it. For that, PA's
        // ConfigurablePool is created inside the V8 Cage during
        // initialization. As such, here all we need to do is indicate that
        // we'd like to use that Pool if it has been created by now (if it
        // hasn't been created, the cage isn't enabled, and so we'll use the
        // default Pool).
        opts.use_configurable_pool =
            partition_alloc::PartitionOptions::kAllowed;
        opts.memory_tagging = {
            .enabled = partition_alloc::PartitionOptions::kDisabled};
        return opts;
      }());

  array_buffer_root_ = array_buffer_allocator->root();
}

// static
void Partitions::StartMemoryReclaimer(
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  CHECK(IsMainThread());
  DCHECK(initialized_);

  base::allocator::StartMemoryReclaimer(task_runner);
}

// static
void Partitions::DumpMemoryStats(
    bool is_light_dump,
    partition_alloc::PartitionStatsDumper* partition_stats_dumper) {
  // Object model and rendering partitions are not thread safe and can be
  // accessed only on the main thread.
  DCHECK(IsMainThread());

  if (auto* fast_malloc_partition = FastMallocPartition()) {
    fast_malloc_partition->DumpStats("fast_malloc", is_light_dump,
                                     partition_stats_dumper);
  }
  if (ArrayBufferPartitionInitialized()) {
    ArrayBufferPartition()->DumpStats("array_buffer", is_light_dump,
                                      partition_stats_dumper);
  }
  BufferPartition()->DumpStats("buffer", is_light_dump, partition_stats_dumper);
}

namespace {

class LightPartitionStatsDumperImpl
    : public partition_alloc::PartitionStatsDumper {
 public:
  LightPartitionStatsDumperImpl() : total_active_bytes_(0) {}

  void PartitionDumpTotals(
      const char* partition_name,
      const partition_alloc::PartitionMemoryStats* memory_stats) override {
    total_active_bytes_ += memory_stats->total_active_bytes;
  }

  void PartitionsDumpBucketStats(
      const char* partition_name,
      const partition_alloc::PartitionBucketMemoryStats*) override {}

  size_t TotalActiveBytes() const { return total_active_bytes_; }

 private:
  size_t total_active_bytes_;
};

}  // namespace

// static
size_t Partitions::TotalSizeOfCommittedPages() {
  DCHECK(initialized_);
  size_t total_size = 0;
  // Racy reads below: this is fine to collect statistics.
  if (auto* fast_malloc_partition = FastMallocPartition()) {
    total_size +=
        TS_UNCHECKED_READ(fast_malloc_partition->total_size_of_committed_pages);
  }
  if (ArrayBufferPartitionInitialized()) {
    total_size += TS_UNCHECKED_READ(
        ArrayBufferPartition()->total_size_of_committed_pages);
  }
  total_size +=
      TS_UNCHECKED_READ(BufferPartition()->total_size_of_committed_pages);
  return total_size;
}

// static
size_t Partitions::TotalActiveBytes() {
  LightPartitionStatsDumperImpl dumper;
  WTF::Partitions::DumpMemoryStats(true, &dumper);
  return dumper.TotalActiveBytes();
}

NOINLINE static void PartitionsOutOfMemoryUsing2G(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 2UL * 1024 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing1G(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 1UL * 1024 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing512M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 512 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing256M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 256 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing128M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 128 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing64M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 64 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing32M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 32 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsing16M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 16 * 1024 * 1024;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

NOINLINE static void PartitionsOutOfMemoryUsingLessThan16M(size_t size) {
  NO_CODE_FOLDING();
  size_t signature = 16 * 1024 * 1024 - 1;
  base::debug::Alias(&signature);
  OOM_CRASH(size);
}

// static
void* Partitions::BufferMalloc(size_t n, const char* type_name) {
  return BufferPartition()->Alloc(n, type_name);
}

// static
void* Partitions::BufferTryRealloc(void* p, size_t n, const char* type_name) {
  return BufferPartition()->Realloc<partition_alloc::AllocFlags::kReturnNull>(
      p, n, type_name);
}

// static
void Partitions::BufferFree(void* p) {
  BufferPartition()->Free(p);
}

// static
size_t Partitions::BufferPotentialCapacity(size_t n) {
  return BufferPartition()->AllocationCapacityFromRequestedSize(n);
}

// Ideally this would be removed when PartitionAlloc is malloc(), but there are
// quite a few callers. Just forward to the C functions instead.  Most of the
// usual callers will never reach here though, as USING_FAST_MALLOC() becomes a
// no-op.
// static
void* Partitions::FastMalloc(size_t n, const char* type_name) {
  auto* fast_malloc_partition = FastMallocPartition();
  if (fast_malloc_partition) [[unlikely]] {
    return fast_malloc_partition->Alloc(n, type_name);
  } else {
    return malloc(n);
  }
}

// static
void* Partitions::FastZeroedMalloc(size_t n, const char* type_name) {
  auto* fast_malloc_partition = FastMallocPartition();
  if (fast_malloc_partition) [[unlikely]] {
    return fast_malloc_partition
        ->AllocInline<partition_alloc::AllocFlags::kZeroFill>(n, type_name);
  } else {
    return calloc(n, 1);
  }
}

// static
void Partitions::FastFree(void* p) {
  auto* fast_malloc_partition = FastMallocPartition();
  if (fast_malloc_partition) [[unlikely]] {
    fast_malloc_partition->Free(p);
  } else {
    free(p);
  }
}

// static
void Partitions::HandleOutOfMemory(size_t size) {
  volatile size_t total_usage = TotalSizeOfCommittedPages();
  uint32_t alloc_page_error_code = partition_alloc::GetAllocPageErrorCode();
  base::debug::Alias(&alloc_page_error_code);

  // Report the total mapped size from PageAllocator. This is intended to
  // distinguish better between address space exhaustion and out of memory on 32
  // bit platforms. PartitionAlloc can use a lot of address space, as free pages
  // are not shared between buckets (see crbug.com/421387). There is already
  // reporting for this, however it only looks at the address space usage of a
  // single partition. This allows to look across all the partitions, and other
  // users such as V8.
  char value[24];
  // %d works for 64 bit types as well with SafeSPrintf(), see its unit tests
  // for an example.
  base::strings::SafeSPrintf(value, "%d",
                             partition_alloc::GetTotalMappedSize());
  static crash_reporter::CrashKeyString<24> g_page_allocator_mapped_size(
      "page-allocator-mapped-size");
  g_page_allocator_mapped_size.Set(value);

  if (total_usage >= 2UL * 1024 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing2G(size);
  }
  if (total_usage >= 1UL * 1024 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing1G(size);
  }
  if (total_usage >= 512 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing512M(size);
  }
  if (total_usage >= 256 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing256M(size);
  }
  if (total_usage >= 128 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing128M(size);
  }
  if (total_usage >= 64 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing64M(size);
  }
  if (total_usage >= 32 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing32M(size);
  }
  if (total_usage >= 16 * 1024 * 1024) {
    PartitionsOutOfMemoryUsing16M(size);
  }
  PartitionsOutOfMemoryUsingLessThan16M(size);
}

// static
void Partitions::AdjustPartitionsForForeground() {
  DCHECK(initialized_);
  if (base::FeatureList::IsEnabled(
          base::features::kPartitionAllocAdjustSizeWhenInForeground)) {
    array_buffer_root_->AdjustForForeground();
    buffer_root_->AdjustForForeground();
    if (fast_malloc_root_) {
      fast_malloc_root_->AdjustForForeground();
    }
  }
}

// static
void Partitions::AdjustPartitionsForBackground() {
  DCHECK(initialized_);
  if (base::FeatureList::IsEnabled(
          base::features::kPartitionAllocAdjustSizeWhenInForeground)) {
    array_buffer_root_->AdjustForBackground();
    buffer_root_->AdjustForBackground();
    if (fast_malloc_root_) {
      fast_malloc_root_->AdjustForBackground();
    }
  }
}

}  // namespace WTF
```