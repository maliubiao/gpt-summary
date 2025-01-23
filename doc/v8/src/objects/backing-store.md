Response: Let's break down the thought process for analyzing the `backing-store.cc` file and generating the summary.

1. **Understand the Goal:** The request is to summarize the functionality of the C++ code and illustrate its connection to JavaScript using examples.

2. **Initial Scan for Keywords and Structure:**  Start by skimming the code for important keywords and structural elements. Look for:
    * `#include` statements: These indicate dependencies and the kinds of functionalities involved (e.g., `objects`, `execution`, `handles`, `wasm`). The heavy presence of `wasm` hints at a significant role for WebAssembly.
    * Class names: `BackingStore`, `GlobalBackingStoreRegistry`. These are core components.
    * Function names: `Allocate`, `Free`, `Grow`, `Resize`, `WrapAllocation`. These suggest memory management operations.
    * Namespaces: `v8::internal`. This confirms it's internal V8 code.
    * Macros: `TRACE_BS`. This is likely for debugging/logging.
    * Conditional compilation: `#if V8_ENABLE_WEBASSEMBLY`. This reinforces the WebAssembly connection.
    * Data members within the `BackingStore` class: `buffer_start_`, `byte_length_`, `max_byte_length_`, `is_shared_`, `is_wasm_memory_`. These describe the state of a backing store.

3. **Identify Core Functionality:** Based on the initial scan, the core functionality seems to be managing memory buffers, particularly for ArrayBuffers and WebAssembly memory. The `BackingStore` class is central to this.

4. **Analyze `BackingStore` Class:**
    * **Constructor/Destructor:**  Pay close attention to how `BackingStore` instances are created and destroyed. The constructor takes various flags related to sharing, resizability, and WebAssembly. The destructor handles deallocation, including different logic for Wasm memory and regular ArrayBuffers.
    * **Allocation Methods (`Allocate`, `AllocateWasmMemory`, `TryAllocateAndPartiallyCommitMemory`):**  Notice different allocation paths for different scenarios (regular ArrayBuffers, Wasm memories, resizable buffers). The `TryAllocateAndPartiallyCommitMemory` function appears more complex and likely handles page-level memory management, which is common for Wasm.
    * **Modification Methods (`Grow`, `Resize`, `GrowWasmMemoryInPlace`):** These methods deal with changing the size of the underlying memory. The "InPlace" variants suggest trying to avoid costly reallocation.
    * **Wrapping (`WrapAllocation`):** This indicates the ability to manage externally allocated memory.
    * **Flags and State:** Understand the purpose of members like `is_shared_`, `is_resizable_by_js_`, `is_wasm_memory_`, and how they influence the behavior of different methods.

5. **Analyze `GlobalBackingStoreRegistry`:**
    * **Purpose:**  The name suggests it manages a collection of `BackingStore` objects. The methods (`Register`, `Unregister`, `Purge`, `AddSharedWasmMemoryObject`, `BroadcastSharedWasmMemoryGrow`, `UpdateSharedWasmMemoryObjects`) strongly indicate its role in managing *shared* WebAssembly memory. It's tracking which isolates are using a particular shared memory.
    * **Concurrency:** The presence of `base::Mutex` suggests thread safety and the need to manage concurrent access to shared memory.

6. **Connect to JavaScript:**
    * **`ArrayBuffer` and `SharedArrayBuffer`:** These are the most direct JavaScript counterparts. The code clearly deals with allocating and managing the underlying memory for these objects.
    * **WebAssembly `Memory`:**  The extensive use of `#if V8_ENABLE_WEBASSEMBLY` and functions like `AllocateWasmMemory` point directly to the management of WebAssembly linear memory.
    * **Resizing and Growing:**  Relate the C++ `Resize` and `Grow` methods to the JavaScript methods like `ArrayBuffer.prototype.resize()` and `SharedArrayBuffer.prototype.grow()` (and the experimental `WebAssembly.Memory.prototype.grow()`).
    * **External Allocation:** Connect `WrapAllocation` to scenarios where JavaScript might interact with memory allocated outside of V8's usual mechanisms.

7. **Construct the Summary:**  Organize the findings into a coherent summary.
    * Start with a high-level overview of the file's purpose.
    * Detail the functionality of the `BackingStore` class, focusing on allocation, deallocation, resizing, and the different types of backing stores (regular, Wasm, shared, resizable).
    * Explain the role of `GlobalBackingStoreRegistry` in managing shared WebAssembly memory.
    * Provide clear JavaScript examples to illustrate the connection between the C++ code and JavaScript concepts. Focus on demonstrating how JavaScript operations interact with the underlying backing store.

8. **Refine and Review:**  Read through the summary to ensure clarity, accuracy, and completeness. Check for any logical gaps or areas that need further explanation. Make sure the JavaScript examples are correct and effectively demonstrate the concepts. For instance, initially, I might have just said "manages ArrayBuffers," but refining that to explain the differences between `ArrayBuffer` and `SharedArrayBuffer` is important. Similarly, explicitly mentioning the page-level allocation for Wasm is a key detail.

By following this structured approach, moving from a broad overview to specific details and then connecting the C++ code to its JavaScript manifestations, a comprehensive and accurate summary can be generated.
这个 C++ 源代码文件 `backing-store.cc` 定义了 `v8::internal::BackingStore` 类及其相关的辅助功能，主要负责 **管理和维护 ArrayBuffer 和 WebAssembly Memory 对象背后的实际内存缓冲区**。

以下是它的主要功能归纳：

**核心功能：管理内存缓冲区**

* **分配 (Allocate):** 提供多种方法来分配内存缓冲区，包括：
    * 为普通的 `ArrayBuffer` 分配内存，使用 embedder 提供的 `v8::ArrayBuffer::Allocator`。
    * 为 WebAssembly 的 `Memory` 对象分配内存，使用页分配器 (PageAllocator)，并支持添加保护页 (guard regions) 以进行越界访问检测。
    * 支持分配可调整大小的 ArrayBuffer (`ResizableArrayBuffer`)。
    * 支持分配共享的 ArrayBuffer (`SharedArrayBuffer`) 和 WebAssembly Memory。
* **释放 (Free):**  负责释放不再使用的内存缓冲区，根据不同的分配方式调用相应的释放方法，例如：
    * 使用 embedder 提供的 `v8::ArrayBuffer::Allocator` 释放普通 `ArrayBuffer` 的内存。
    * 使用页分配器释放 WebAssembly `Memory` 或可调整大小 `ArrayBuffer` 的内存。
    * 支持自定义的释放回调函数 (custom deleter)。
* **调整大小 (Resize/Grow):** 提供方法来调整现有内存缓冲区的大小：
    * 对于普通的 `ArrayBuffer`，可以重新分配内存 (Reallocate)。
    * 对于可调整大小的 `ArrayBuffer` 和 WebAssembly `Memory`，可以在原地扩展或收缩内存（如果操作系统支持），避免重新分配和拷贝的开销。
    * 对于共享的 `SharedArrayBuffer`，提供原子性的增长操作 (`GrowInPlace`)。
* **包装外部内存 (WrapAllocation):** 允许 V8 管理由外部（非 V8 分配器）分配的内存缓冲区。
* **记录分配状态 (RecordStatus):** 用于将内存分配的结果报告给 UMA (User Metrics Analysis)。

**WebAssembly 特性支持：**

* **保护页 (Guard Regions):** 为 WebAssembly `Memory` 分配内存时，可以在内存区域的两端添加保护页，用于捕获越界访问错误，这与 WebAssembly 的陷阱处理机制有关。
* **共享内存管理 (Shared Memory):**  专门处理共享的 WebAssembly `Memory` 对象的生命周期和跨 Isolate 的同步：
    * 维护一个全局注册表 (`GlobalBackingStoreRegistry`)，记录所有共享的 WebAssembly `Memory` 对象的 `BackingStore`。
    * 跟踪哪些 Isolate 正在使用特定的共享内存。
    * 在共享内存增长时，通知其他共享该内存的 Isolate。
    * 在垃圾回收时，清理不再使用的共享内存对象的引用。

**与 JavaScript 的关系：**

`BackingStore` 是 JavaScript 中 `ArrayBuffer`、`SharedArrayBuffer` 和 WebAssembly `Memory` 对象的底层实现。当你创建一个 `ArrayBuffer` 或 `SharedArrayBuffer`，或者实例化一个 WebAssembly `Memory` 对象时，V8 内部会创建一个 `BackingStore` 对象来管理其底层的内存缓冲区。

**JavaScript 示例：**

1. **创建 `ArrayBuffer`:**

   ```javascript
   const buffer = new ArrayBuffer(1024); // 在 C++ 中会分配一个 1024 字节的 BackingStore
   console.log(buffer.byteLength); // 输出 1024
   ```

2. **创建 `SharedArrayBuffer`:**

   ```javascript
   const sharedBuffer = new SharedArrayBuffer(1024); // 在 C++ 中会分配一个共享的 BackingStore
   console.log(sharedBuffer.byteLength); // 输出 1024
   ```

3. **创建 WebAssembly `Memory`:**

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1, maximum: 10 }); // 在 C++ 中会分配一个带保护页的 BackingStore
   console.log(memory.buffer.byteLength); // 输出初始大小，例如 65536 (64KB)
   ```

4. **调整 `ArrayBuffer` 大小 (使用实验性 API):**

   ```javascript
   const buffer = new ArrayBuffer(1024, { resizable: true });
   console.log(buffer.byteLength); // 输出 1024

   buffer.resize(2048); // 在 C++ 中可能会调用 BackingStore 的 ResizeInPlace 或 Reallocate
   console.log(buffer.byteLength); // 输出 2048
   ```

5. **增长 `SharedArrayBuffer`:**

   ```javascript
   const sab = new SharedArrayBuffer(1024, { maxByteLength: 2048 });
   console.log(sab.byteLength); // 输出 1024

   // 需要在原子操作中获取增长后的长度
   Atomics.add(new Int32Array(sab), 0, 0); // 触发增长的条件 (实际增长逻辑可能更复杂)
   // ... 后续操作会反映增长后的长度
   ```

6. **增长 WebAssembly `Memory`:**

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1, maximum: 10 });
   const oldSize = memory.buffer.byteLength;
   memory.grow(1); // 在 C++ 中会调用 BackingStore 的 GrowWasmMemoryInPlace
   const newSize = memory.buffer.byteLength;
   console.log(newSize > oldSize); // 输出 true
   ```

**总结：**

`backing-store.cc` 文件是 V8 引擎中管理内存缓冲区的关键组成部分，它直接支撑着 JavaScript 中 `ArrayBuffer`、`SharedArrayBuffer` 和 WebAssembly `Memory` 的功能。它处理了内存的分配、释放、调整大小以及与 WebAssembly 特性（如保护页和共享内存）的集成。理解 `BackingStore` 的工作原理有助于深入理解 JavaScript 中二进制数据处理和 WebAssembly 的内存模型。

### 提示词
```
这是目录为v8/src/objects/backing-store.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/backing-store.h"

#include <cstring>
#include <optional>

#include "src/base/bits.h"
#include "src/execution/isolate.h"
#include "src/handles/global-handles.h"
#include "src/logging/counters.h"
#include "src/sandbox/sandbox.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#define TRACE_BS(...)                                      \
  do {                                                     \
    if (v8_flags.trace_backing_store) PrintF(__VA_ARGS__); \
  } while (false)

namespace v8::internal {

namespace {

#if V8_ENABLE_WEBASSEMBLY && V8_TARGET_ARCH_64_BIT
constexpr size_t kFullGuardSize32 = uint64_t{8} * GB;
#endif

std::atomic<uint32_t> next_backing_store_id_{1};

// Allocation results are reported to UMA
//
// See wasm_memory_allocation_result in counters-definitions.h
enum class AllocationStatus {
  kSuccess,  // Succeeded on the first try

  kSuccessAfterRetry,  // Succeeded after garbage collection

  kAddressSpaceLimitReachedFailure,  // Failed because Wasm is at its address
                                     // space limit

  kOtherFailure  // Failed for an unknown reason
};

size_t GetReservationSize(bool has_guard_regions, size_t byte_capacity,
                          bool is_wasm_memory64) {
#if V8_TARGET_ARCH_64_BIT && V8_ENABLE_WEBASSEMBLY
  DCHECK_IMPLIES(is_wasm_memory64 && has_guard_regions,
                 v8_flags.wasm_memory64_trap_handling);
  if (has_guard_regions && !is_wasm_memory64) {
    static_assert(kFullGuardSize32 >= size_t{4} * GB);
    DCHECK_LE(byte_capacity, size_t{4} * GB);
    return kFullGuardSize32;
  }
#else
  DCHECK(!has_guard_regions);
#endif

  return byte_capacity;
}

base::AddressRegion GetReservedRegion(bool has_guard_regions,
                                      bool is_wasm_memory64, void* buffer_start,
                                      size_t byte_capacity) {
  return base::AddressRegion(
      reinterpret_cast<Address>(buffer_start),
      GetReservationSize(has_guard_regions, byte_capacity, is_wasm_memory64));
}

void RecordStatus(Isolate* isolate, AllocationStatus status) {
  isolate->counters()->wasm_memory_allocation_result()->AddSample(
      static_cast<int>(status));
}

}  // namespace

// The backing store for a Wasm shared memory remembers all the isolates
// with which it has been shared.
struct SharedWasmMemoryData {
  std::vector<Isolate*> isolates_;
};

BackingStore::BackingStore(void* buffer_start, size_t byte_length,
                           size_t max_byte_length, size_t byte_capacity,
                           SharedFlag shared, ResizableFlag resizable,
                           bool is_wasm_memory, bool is_wasm_memory64,
                           bool has_guard_regions, bool custom_deleter,
                           bool empty_deleter)
    : buffer_start_(buffer_start),
      byte_length_(byte_length),
      max_byte_length_(max_byte_length),
      byte_capacity_(byte_capacity),
      id_(next_backing_store_id_.fetch_add(1)),
      is_shared_(shared == SharedFlag::kShared),
      is_resizable_by_js_(resizable == ResizableFlag::kResizable),
      is_wasm_memory_(is_wasm_memory),
      is_wasm_memory64_(is_wasm_memory64),
      holds_shared_ptr_to_allocator_(false),
      has_guard_regions_(has_guard_regions),
      globally_registered_(false),
      custom_deleter_(custom_deleter),
      empty_deleter_(empty_deleter) {
  // TODO(v8:11111): RAB / GSAB - Wasm integration.
  DCHECK_IMPLIES(is_wasm_memory_, !is_resizable_by_js_);
  DCHECK_IMPLIES(is_resizable_by_js_, !custom_deleter_);
  DCHECK_IMPLIES(!is_wasm_memory && !is_resizable_by_js_,
                 byte_length_ == max_byte_length_);
  DCHECK_GE(max_byte_length_, byte_length_);
  DCHECK_GE(byte_capacity_, max_byte_length_);
  // TODO(1445003): Demote to a DCHECK once we found the issue.
  // Wasm memory should never be empty (== zero capacity). Otherwise
  // {JSArrayBuffer::Attach} would replace it by the {EmptyBackingStore} and we
  // loose information.
  // This is particularly important for shared Wasm memory.
  CHECK_IMPLIES(is_wasm_memory_, byte_capacity_ != 0);
}

BackingStore::~BackingStore() {
  GlobalBackingStoreRegistry::Unregister(this);

  struct ClearSharedAllocator {
    BackingStore* const bs;

    ~ClearSharedAllocator() {
      if (!bs->holds_shared_ptr_to_allocator_) return;
      bs->type_specific_data_.v8_api_array_buffer_allocator_shared
          .std::shared_ptr<v8::ArrayBuffer::Allocator>::~shared_ptr();
    }
  } clear_shared_allocator{this};

  if (buffer_start_ == nullptr) return;

  auto FreeResizableMemory = [this] {
    DCHECK(!custom_deleter_);
    DCHECK(is_resizable_by_js_ || is_wasm_memory_);
    auto region = GetReservedRegion(has_guard_regions_, is_wasm_memory64_,
                                    buffer_start_, byte_capacity_);

    PageAllocator* page_allocator = GetArrayBufferPageAllocator();
    if (!region.is_empty()) {
      FreePages(page_allocator, reinterpret_cast<void*>(region.begin()),
                region.size());
    }
  };

#if V8_ENABLE_WEBASSEMBLY
  if (is_wasm_memory_) {
    // TODO(v8:11111): RAB / GSAB - Wasm integration.
    DCHECK(!is_resizable_by_js_);
    size_t reservation_size = GetReservationSize(
        has_guard_regions_, byte_capacity_, is_wasm_memory64_);
    TRACE_BS(
        "BSw:free  bs=%p mem=%p (length=%zu, capacity=%zu, reservation=%zu)\n",
        this, buffer_start_, byte_length(), byte_capacity_, reservation_size);
    if (is_shared_) {
      // Deallocate the list of attached memory objects.
      SharedWasmMemoryData* shared_data = get_shared_wasm_memory_data();
      delete shared_data;
    }
    // Wasm memories are always allocated through the page allocator.
    FreeResizableMemory();
    return;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (is_resizable_by_js_) {
    FreeResizableMemory();
    return;
  }

  if (custom_deleter_) {
    TRACE_BS("BS:custom deleter bs=%p mem=%p (length=%zu, capacity=%zu)\n",
             this, buffer_start_, byte_length(), byte_capacity_);
    type_specific_data_.deleter.callback(buffer_start_, byte_length_,
                                         type_specific_data_.deleter.data);
    return;
  }

  // JSArrayBuffer backing store. Deallocate through the embedder's allocator.
  auto allocator = get_v8_api_array_buffer_allocator();
  TRACE_BS("BS:free   bs=%p mem=%p (length=%zu, capacity=%zu)\n", this,
           buffer_start_, byte_length(), byte_capacity_);
  allocator->Free(buffer_start_, byte_length_);
}

// Allocate a backing store using the array buffer allocator from the embedder.
std::unique_ptr<BackingStore> BackingStore::Allocate(
    Isolate* isolate, size_t byte_length, SharedFlag shared,
    InitializedFlag initialized) {
  void* buffer_start = nullptr;
  auto allocator = isolate->array_buffer_allocator();
  CHECK_NOT_NULL(allocator);
  if (byte_length != 0) {
    auto counters = isolate->counters();
    int mb_length = static_cast<int>(byte_length / MB);
    if (mb_length > 0) {
      counters->array_buffer_big_allocations()->AddSample(mb_length);
    }
    if (shared == SharedFlag::kShared) {
      counters->shared_array_allocations()->AddSample(mb_length);
    }
    auto allocate_buffer = [allocator, initialized](size_t byte_length) {
      if (initialized == InitializedFlag::kUninitialized) {
        return allocator->AllocateUninitialized(byte_length);
      }
      return allocator->Allocate(byte_length);
    };

    buffer_start = isolate->heap()->AllocateExternalBackingStore(
        allocate_buffer, byte_length);

    if (buffer_start == nullptr) {
      // Allocation failed.
      counters->array_buffer_new_size_failures()->AddSample(mb_length);
      return {};
    }
#ifdef V8_ENABLE_SANDBOX
    // Check to catch use of a non-sandbox-compatible ArrayBufferAllocator.
    CHECK_WITH_MSG(GetProcessWideSandbox()->Contains(buffer_start),
                   "When the V8 Sandbox is enabled, ArrayBuffer backing stores "
                   "must be allocated inside the sandbox address space. Please "
                   "use an appropriate ArrayBuffer::Allocator to allocate "
                   "these buffers, or disable the sandbox.");
#endif
  }

  auto result = new BackingStore(buffer_start,                  // start
                                 byte_length,                   // length
                                 byte_length,                   // max length
                                 byte_length,                   // capacity
                                 shared,                        // shared
                                 ResizableFlag::kNotResizable,  // resizable
                                 false,   // is_wasm_memory
                                 false,   // is_wasm_memory64
                                 false,   // has_guard_regions
                                 false,   // custom_deleter
                                 false);  // empty_deleter

  TRACE_BS("BS:alloc  bs=%p mem=%p (length=%zu)\n", result,
           result->buffer_start(), byte_length);
  result->SetAllocatorFromIsolate(isolate);
  return std::unique_ptr<BackingStore>(result);
}

void BackingStore::SetAllocatorFromIsolate(Isolate* isolate) {
  if (auto allocator_shared = isolate->array_buffer_allocator_shared()) {
    holds_shared_ptr_to_allocator_ = true;
    new (&type_specific_data_.v8_api_array_buffer_allocator_shared)
        std::shared_ptr<v8::ArrayBuffer::Allocator>(
            std::move(allocator_shared));
  } else {
    type_specific_data_.v8_api_array_buffer_allocator =
        isolate->array_buffer_allocator();
  }
}

std::unique_ptr<BackingStore> BackingStore::TryAllocateAndPartiallyCommitMemory(
    Isolate* isolate, size_t byte_length, size_t max_byte_length,
    size_t page_size, size_t initial_pages, size_t maximum_pages,
    WasmMemoryFlag wasm_memory, SharedFlag shared) {
  // Enforce engine limitation on the maximum number of pages.
  if (maximum_pages > std::numeric_limits<size_t>::max() / page_size) {
    return nullptr;
  }

  // Cannot reserve 0 pages on some OSes.
  if (maximum_pages == 0) maximum_pages = 1;

  TRACE_BS("BSw:try   %zu pages, %zu max\n", initial_pages, maximum_pages);

#if V8_ENABLE_WEBASSEMBLY
  bool is_wasm_memory64 = wasm_memory == WasmMemoryFlag::kWasmMemory64;
  bool guards = trap_handler::IsTrapHandlerEnabled() &&
                (wasm_memory == WasmMemoryFlag::kWasmMemory32 ||
                 (is_wasm_memory64 && v8_flags.wasm_memory64_trap_handling));
#else
  CHECK_EQ(WasmMemoryFlag::kNotWasm, wasm_memory);
  constexpr bool is_wasm_memory64 = false;
  constexpr bool guards = false;
#endif  // V8_ENABLE_WEBASSEMBLY

  // For accounting purposes, whether a GC was necessary.
  bool did_retry = false;

  // A helper to try running a function up to 3 times, executing a GC
  // if the first and second attempts failed.
  auto gc_retry = [&](const std::function<bool()>& fn) {
    for (int i = 0; i < 3; i++) {
      if (fn()) return true;
      // Collect garbage and retry.
      did_retry = true;
      if (isolate != nullptr) {
        isolate->heap()->MemoryPressureNotification(
            MemoryPressureLevel::kCritical, true);
      }
    }
    return false;
  };

  size_t byte_capacity = maximum_pages * page_size;
  size_t reservation_size =
      GetReservationSize(guards, byte_capacity, is_wasm_memory64);

  //--------------------------------------------------------------------------
  // Allocate pages (inaccessible by default).
  //--------------------------------------------------------------------------
  void* allocation_base = nullptr;
  PageAllocator* page_allocator = GetArrayBufferPageAllocator();
  auto allocate_pages = [&] {
    allocation_base = AllocatePages(page_allocator, nullptr, reservation_size,
                                    page_size, PageAllocator::kNoAccess);
    return allocation_base != nullptr;
  };
  if (!gc_retry(allocate_pages)) {
    // Page allocator could not reserve enough pages.
    if (isolate != nullptr) {
      RecordStatus(isolate, AllocationStatus::kOtherFailure);
    }
    TRACE_BS("BSw:try   failed to allocate pages\n");
    return {};
  }

  uint8_t* buffer_start = reinterpret_cast<uint8_t*>(allocation_base);

  //--------------------------------------------------------------------------
  // Commit the initial pages (allow read/write).
  //--------------------------------------------------------------------------
  size_t committed_byte_length = initial_pages * page_size;
  auto commit_memory = [&] {
    return committed_byte_length == 0 ||
           SetPermissions(page_allocator, buffer_start, committed_byte_length,
                          PageAllocator::kReadWrite);
  };
  if (!gc_retry(commit_memory)) {
    TRACE_BS("BSw:try   failed to set permissions (%p, %zu)\n", buffer_start,
             committed_byte_length);
    FreePages(page_allocator, allocation_base, reservation_size);
    // SetPermissions put us over the process memory limit.
    // We return an empty result so that the caller can throw an exception.
    return {};
  }

  if (isolate != nullptr) {
    RecordStatus(isolate, did_retry ? AllocationStatus::kSuccessAfterRetry
                                    : AllocationStatus::kSuccess);
  }

  const bool is_wasm_memory = wasm_memory != WasmMemoryFlag::kNotWasm;
  ResizableFlag resizable =
      is_wasm_memory ? ResizableFlag::kNotResizable : ResizableFlag::kResizable;

  auto result = new BackingStore(buffer_start,      // start
                                 byte_length,       // length
                                 max_byte_length,   // max_byte_length
                                 byte_capacity,     // capacity
                                 shared,            // shared
                                 resizable,         // resizable
                                 is_wasm_memory,    // is_wasm_memory
                                 is_wasm_memory64,  // is_wasm_memory64
                                 guards,            // has_guard_regions
                                 false,             // custom_deleter
                                 false);            // empty_deleter
  TRACE_BS(
      "BSw:alloc bs=%p mem=%p (length=%zu, capacity=%zu, reservation=%zu)\n",
      result, result->buffer_start(), byte_length, byte_capacity,
      reservation_size);

  return std::unique_ptr<BackingStore>(result);
}

#if V8_ENABLE_WEBASSEMBLY
// Allocate a backing store for a Wasm memory. Always use the page allocator
// and add guard regions.
std::unique_ptr<BackingStore> BackingStore::AllocateWasmMemory(
    Isolate* isolate, size_t initial_pages, size_t maximum_pages,
    WasmMemoryFlag wasm_memory, SharedFlag shared) {
  // Wasm pages must be a multiple of the allocation page size.
  DCHECK_EQ(0, wasm::kWasmPageSize % AllocatePageSize());
  DCHECK_LE(initial_pages, maximum_pages);

  DCHECK(wasm_memory == WasmMemoryFlag::kWasmMemory32 ||
         wasm_memory == WasmMemoryFlag::kWasmMemory64);

  auto TryAllocate = [isolate, initial_pages, wasm_memory,
                      shared](size_t maximum_pages) {
    auto result = TryAllocateAndPartiallyCommitMemory(
        isolate, initial_pages * wasm::kWasmPageSize,
        maximum_pages * wasm::kWasmPageSize, wasm::kWasmPageSize, initial_pages,
        maximum_pages, wasm_memory, shared);
    if (result && shared == SharedFlag::kShared) {
      result->type_specific_data_.shared_wasm_memory_data =
          new SharedWasmMemoryData();
    }
    return result;
  };
  auto backing_store = TryAllocate(maximum_pages);
  if (!backing_store && maximum_pages - initial_pages >= 4) {
    // Retry with smaller maximum pages at each retry.
    auto delta = (maximum_pages - initial_pages) / 4;
    size_t sizes[] = {maximum_pages - delta, maximum_pages - 2 * delta,
                      maximum_pages - 3 * delta, initial_pages};

    for (size_t reduced_maximum_pages : sizes) {
      backing_store = TryAllocate(reduced_maximum_pages);
      if (backing_store) break;
    }
  }
  return backing_store;
}

std::unique_ptr<BackingStore> BackingStore::CopyWasmMemory(
    Isolate* isolate, size_t new_pages, size_t max_pages,
    WasmMemoryFlag wasm_memory) {
  // Note that we could allocate uninitialized to save initialization cost here,
  // but since Wasm memories are allocated by the page allocator, the zeroing
  // cost is already built-in.
  auto new_backing_store = BackingStore::AllocateWasmMemory(
      isolate, new_pages, max_pages, wasm_memory,
      is_shared() ? SharedFlag::kShared : SharedFlag::kNotShared);

  if (!new_backing_store ||
      new_backing_store->has_guard_regions() != has_guard_regions_) {
    return {};
  }

  if (byte_length_ > 0) {
    // If the allocation was successful, then the new buffer must be at least
    // as big as the old one.
    DCHECK_GE(new_pages * wasm::kWasmPageSize, byte_length_);
    memcpy(new_backing_store->buffer_start(), buffer_start_, byte_length_);
  }

  return new_backing_store;
}

// Try to grow the size of a wasm memory in place, without realloc + copy.
std::optional<size_t> BackingStore::GrowWasmMemoryInPlace(Isolate* isolate,
                                                          size_t delta_pages,
                                                          size_t max_pages) {
  // This function grows wasm memory by
  // * changing the permissions of additional {delta_pages} pages to kReadWrite;
  // * increment {byte_length_};
  //
  // As this code is executed concurrently, the following steps are executed:
  // 1) Read the current value of {byte_length_};
  // 2) Change the permission of all pages from {buffer_start_} to
  //    {byte_length_} + {delta_pages} * {page_size} to kReadWrite;
  //    * This operation may be executed racefully. The OS takes care of
  //      synchronization.
  // 3) Try to update {byte_length_} with a compare_exchange;
  // 4) Repeat 1) to 3) until the compare_exchange in 3) succeeds;
  //
  // The result of this function is the {byte_length_} before growing in pages.
  // The result of this function appears like the result of an RMW-update on
  // {byte_length_}, i.e. two concurrent calls to this function will result in
  // different return values if {delta_pages} != 0.
  //
  // Invariants:
  // * Permissions are always set incrementally, i.e. for any page {b} with
  //   kReadWrite permission, all pages between the first page {a} and page {b}
  //   also have kReadWrite permission.
  // * {byte_length_} is always lower or equal than the amount of memory with
  //   permissions set to kReadWrite;
  //     * This is guaranteed by incrementing {byte_length_} with a
  //       compare_exchange after changing the permissions.
  //     * This invariant is the reason why we cannot use a fetch_add.
  DCHECK(is_wasm_memory_);
  max_pages = std::min(max_pages, byte_capacity_ / wasm::kWasmPageSize);

  // Do a compare-exchange loop, because we also need to adjust page
  // permissions. Note that multiple racing grows both try to set page
  // permissions for the entire range (to be RW), so the operating system
  // should deal with that raciness. We know we succeeded when we can
  // compare/swap the old length with the new length.
  size_t old_length = byte_length_.load(std::memory_order_relaxed);

  if (delta_pages == 0)
    return {old_length / wasm::kWasmPageSize};  // degenerate grow.
  if (delta_pages > max_pages) return {};       // would never work.

  size_t new_length = 0;
  while (true) {
    size_t current_pages = old_length / wasm::kWasmPageSize;

    // Check if we have exceed the supplied maximum.
    if (current_pages > (max_pages - delta_pages)) return {};

    new_length = (current_pages + delta_pages) * wasm::kWasmPageSize;

    // Try to adjust the permissions on the memory.
    if (!i::SetPermissions(GetPlatformPageAllocator(), buffer_start_,
                           new_length, PageAllocator::kReadWrite)) {
      return {};
    }
    if (byte_length_.compare_exchange_weak(old_length, new_length,
                                           std::memory_order_acq_rel)) {
      // Successfully updated both the length and permissions.
      break;
    }
  }

  return {old_length / wasm::kWasmPageSize};
}

void BackingStore::AttachSharedWasmMemoryObject(
    Isolate* isolate, Handle<WasmMemoryObject> memory_object) {
  DCHECK(is_wasm_memory_);
  DCHECK(is_shared_);
  // We need to take the global registry lock for this operation.
  GlobalBackingStoreRegistry::AddSharedWasmMemoryObject(isolate, this,
                                                        memory_object);
}

void BackingStore::BroadcastSharedWasmMemoryGrow(Isolate* isolate) const {
  GlobalBackingStoreRegistry::BroadcastSharedWasmMemoryGrow(isolate, this);
}

void BackingStore::RemoveSharedWasmMemoryObjects(Isolate* isolate) {
  GlobalBackingStoreRegistry::Purge(isolate);
}

void BackingStore::UpdateSharedWasmMemoryObjects(Isolate* isolate) {
  GlobalBackingStoreRegistry::UpdateSharedWasmMemoryObjects(isolate);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Commit already reserved memory (for RAB backing stores (not shared)).
BackingStore::ResizeOrGrowResult BackingStore::ResizeInPlace(
    Isolate* isolate, size_t new_byte_length) {
  size_t page_size = AllocatePageSize();
  size_t new_committed_pages;
  bool round_return_value =
      RoundUpToPageSize(new_byte_length, page_size,
                        JSArrayBuffer::kMaxByteLength, &new_committed_pages);
  CHECK(round_return_value);

  size_t new_committed_length = new_committed_pages * page_size;
  DCHECK_LE(new_byte_length, new_committed_length);
  DCHECK(!is_shared());

  if (new_byte_length < byte_length_) {
    // Zero the memory so that in case the buffer is grown later, we have
    // zeroed the contents already. This is especially needed for the portion of
    // the memory we're not going to decommit below (since it belongs to a
    // committed page). In addition, we don't rely on all platforms always
    // zeroing decommitted-then-recommitted memory, but zero the memory
    // explicitly here.
    memset(reinterpret_cast<uint8_t*>(buffer_start_) + new_byte_length, 0,
           byte_length_ - new_byte_length);

    // Check if we can un-commit some pages.
    size_t old_committed_pages;
    round_return_value =
        RoundUpToPageSize(byte_length_, page_size,
                          JSArrayBuffer::kMaxByteLength, &old_committed_pages);
    CHECK(round_return_value);
    DCHECK_LE(new_committed_pages, old_committed_pages);

    if (new_committed_pages < old_committed_pages) {
      size_t old_committed_length = old_committed_pages * page_size;
      if (!i::SetPermissions(
              GetPlatformPageAllocator(),
              reinterpret_cast<uint8_t*>(buffer_start_) + new_committed_length,
              old_committed_length - new_committed_length,
              PageAllocator::kNoAccess)) {
        return kFailure;
      }
    }

    // Changing the byte length wouldn't strictly speaking be needed, since
    // the JSArrayBuffer already stores the updated length. This is to keep
    // the BackingStore and JSArrayBuffer in sync.
    byte_length_ = new_byte_length;
    return kSuccess;
  }
  if (new_byte_length == byte_length_) {
    // i::SetPermissions with size 0 fails on some platforms, so special
    // handling for the case byte_length_ == new_byte_length == 0 is required.
    return kSuccess;
  }

  // Try to adjust the permissions on the memory.
  if (!i::SetPermissions(GetPlatformPageAllocator(), buffer_start_,
                         new_committed_length, PageAllocator::kReadWrite)) {
    return kFailure;
  }

  byte_length_ = new_byte_length;
  return kSuccess;
}

// Commit already reserved memory (for GSAB backing stores (shared)).
BackingStore::ResizeOrGrowResult BackingStore::GrowInPlace(
    Isolate* isolate, size_t new_byte_length) {
  size_t page_size = AllocatePageSize();
  size_t new_committed_pages;
  bool round_return_value =
      RoundUpToPageSize(new_byte_length, page_size,
                        JSArrayBuffer::kMaxByteLength, &new_committed_pages);
  CHECK(round_return_value);

  size_t new_committed_length = new_committed_pages * page_size;
  DCHECK_LE(new_byte_length, new_committed_length);
  DCHECK(is_shared());
  // See comment in GrowWasmMemoryInPlace.
  // GrowableSharedArrayBuffer.prototype.grow can be called from several
  // threads. If two threads try to grow() in a racy way, the spec allows the
  // larger grow to throw also if the smaller grow succeeds first. The
  // implementation below doesn't throw in that case - instead, it retries and
  // succeeds. If the larger grow finishes first though, the smaller grow must
  // throw.
  size_t old_byte_length = byte_length_.load(std::memory_order_seq_cst);
  while (true) {
    if (new_byte_length < old_byte_length) {
      // The caller checks for the new_byte_length < old_byte_length_ case. This
      // can only happen if another thread grew the memory after that.
      return kRace;
    }
    if (new_byte_length == old_byte_length) {
      // i::SetPermissions with size 0 fails on some platforms, so special
      // handling for the case old_byte_length == new_byte_length == 0 is
      // required.
      return kSuccess;
    }

    // Try to adjust the permissions on the memory.
    if (!i::SetPermissions(GetPlatformPageAllocator(), buffer_start_,
                           new_committed_length, PageAllocator::kReadWrite)) {
      return kFailure;
    }

    // compare_exchange_weak updates old_byte_length.
    if (byte_length_.compare_exchange_weak(old_byte_length, new_byte_length,
                                           std::memory_order_seq_cst)) {
      // Successfully updated both the length and permissions.
      break;
    }
  }
  return kSuccess;
}

std::unique_ptr<BackingStore> BackingStore::WrapAllocation(
    void* allocation_base, size_t allocation_length,
    v8::BackingStore::DeleterCallback deleter, void* deleter_data,
    SharedFlag shared) {
  bool is_empty_deleter = (deleter == v8::BackingStore::EmptyDeleter);
  auto result = new BackingStore(allocation_base,               // start
                                 allocation_length,             // length
                                 allocation_length,             // max length
                                 allocation_length,             // capacity
                                 shared,                        // shared
                                 ResizableFlag::kNotResizable,  // resizable
                                 false,              // is_wasm_memory
                                 false,              // is_wasm_memory64
                                 false,              // has_guard_regions
                                 true,               // custom_deleter
                                 is_empty_deleter);  // empty_deleter
  result->type_specific_data_.deleter = {deleter, deleter_data};
  TRACE_BS("BS:wrap   bs=%p mem=%p (length=%zu)\n", result,
           result->buffer_start(), result->byte_length());
  return std::unique_ptr<BackingStore>(result);
}

std::unique_ptr<BackingStore> BackingStore::EmptyBackingStore(
    SharedFlag shared) {
  auto result = new BackingStore(nullptr,                       // start
                                 0,                             // length
                                 0,                             // max length
                                 0,                             // capacity
                                 shared,                        // shared
                                 ResizableFlag::kNotResizable,  // resizable
                                 false,   // is_wasm_memory
                                 false,   // is_wasm_memory64
                                 false,   // has_guard_regions
                                 false,   // custom_deleter
                                 false);  // empty_deleter

  return std::unique_ptr<BackingStore>(result);
}

bool BackingStore::Reallocate(Isolate* isolate, size_t new_byte_length) {
  CHECK(CanReallocate());
  auto allocator = get_v8_api_array_buffer_allocator();
  CHECK_EQ(isolate->array_buffer_allocator(), allocator);
  CHECK_EQ(byte_length_, byte_capacity_);
  START_ALLOW_USE_DEPRECATED()
  void* new_start =
      allocator->Reallocate(buffer_start_, byte_length_, new_byte_length);
  END_ALLOW_USE_DEPRECATED()
  if (!new_start) return false;
  buffer_start_ = new_start;
  byte_capacity_ = new_byte_length;
  byte_length_ = new_byte_length;
  max_byte_length_ = new_byte_length;
  return true;
}

v8::ArrayBuffer::Allocator* BackingStore::get_v8_api_array_buffer_allocator() {
  CHECK(!is_wasm_memory_);
  auto array_buffer_allocator =
      holds_shared_ptr_to_allocator_
          ? type_specific_data_.v8_api_array_buffer_allocator_shared.get()
          : type_specific_data_.v8_api_array_buffer_allocator;
  CHECK_NOT_NULL(array_buffer_allocator);
  return array_buffer_allocator;
}

SharedWasmMemoryData* BackingStore::get_shared_wasm_memory_data() const {
  CHECK(is_wasm_memory_ && is_shared_);
  auto shared_wasm_memory_data = type_specific_data_.shared_wasm_memory_data;
  CHECK(shared_wasm_memory_data);
  return shared_wasm_memory_data;
}

namespace {
// Implementation details of GlobalBackingStoreRegistry.
struct GlobalBackingStoreRegistryImpl {
  GlobalBackingStoreRegistryImpl() = default;
  base::Mutex mutex_;
  std::unordered_map<const void*, std::weak_ptr<BackingStore>> map_;
};

DEFINE_LAZY_LEAKY_OBJECT_GETTER(GlobalBackingStoreRegistryImpl,
                                GetGlobalBackingStoreRegistryImpl)
}  // namespace

void GlobalBackingStoreRegistry::Register(
    std::shared_ptr<BackingStore> backing_store) {
  if (!backing_store || !backing_store->buffer_start()) return;
  // Only wasm memory backing stores need to be registered globally.
  CHECK(backing_store->is_wasm_memory());

  GlobalBackingStoreRegistryImpl* impl = GetGlobalBackingStoreRegistryImpl();
  base::MutexGuard scope_lock(&impl->mutex_);
  if (backing_store->globally_registered_) return;
  TRACE_BS("BS:reg    bs=%p mem=%p (length=%zu, capacity=%zu)\n",
           backing_store.get(), backing_store->buffer_start(),
           backing_store->byte_length(), backing_store->byte_capacity());
  std::weak_ptr<BackingStore> weak = backing_store;
  auto result = impl->map_.insert({backing_store->buffer_start(), weak});
  CHECK(result.second);
  backing_store->globally_registered_ = true;
}

void GlobalBackingStoreRegistry::Unregister(BackingStore* backing_store) {
  if (!backing_store->globally_registered_) return;

  CHECK(backing_store->is_wasm_memory());

  DCHECK_NOT_NULL(backing_store->buffer_start());

  GlobalBackingStoreRegistryImpl* impl = GetGlobalBackingStoreRegistryImpl();
  base::MutexGuard scope_lock(&impl->mutex_);
  const auto& result = impl->map_.find(backing_store->buffer_start());
  if (result != impl->map_.end()) {
    DCHECK(!result->second.lock());
    impl->map_.erase(result);
  }
  backing_store->globally_registered_ = false;
}

void GlobalBackingStoreRegistry::Purge(Isolate* isolate) {
  // We need to keep a reference to all backing stores that are inspected
  // in the purging loop below. Otherwise, we might get a deadlock
  // if the temporary backing store reference created in the loop is
  // the last reference. In that case the destructor of the backing store
  // may try to take the &impl->mutex_ in order to unregister itself.
  std::vector<std::shared_ptr<BackingStore>> prevent_destruction_under_lock;
  GlobalBackingStoreRegistryImpl* impl = GetGlobalBackingStoreRegistryImpl();
  base::MutexGuard scope_lock(&impl->mutex_);
  // Purge all entries in the map that refer to the given isolate.
  for (auto& entry : impl->map_) {
    auto backing_store = entry.second.lock();
    prevent_destruction_under_lock.emplace_back(backing_store);
    if (!backing_store) continue;  // skip entries where weak ptr is null
    CHECK(backing_store->is_wasm_memory());
    if (!backing_store->is_shared()) continue;       // skip non-shared memory
    SharedWasmMemoryData* shared_data =
        backing_store->get_shared_wasm_memory_data();
    // Remove this isolate from the isolates list.
    std::vector<Isolate*>& isolates = shared_data->isolates_;
    auto isolates_it = std::find(isolates.begin(), isolates.end(), isolate);
    if (isolates_it != isolates.end()) {
      *isolates_it = isolates.back();
      isolates.pop_back();
    }
    DCHECK_EQ(isolates.end(),
              std::find(isolates.begin(), isolates.end(), isolate));
  }
}

#if V8_ENABLE_WEBASSEMBLY
void GlobalBackingStoreRegistry::AddSharedWasmMemoryObject(
    Isolate* isolate, BackingStore* backing_store,
    Handle<WasmMemoryObject> memory_object) {
  // Add to the weak array list of shared memory objects in the isolate.
  isolate->AddSharedWasmMemory(memory_object);

  // Add the isolate to the list of isolates sharing this backing store.
  GlobalBackingStoreRegistryImpl* impl = GetGlobalBackingStoreRegistryImpl();
  base::MutexGuard scope_lock(&impl->mutex_);
  SharedWasmMemoryData* shared_data =
      backing_store->get_shared_wasm_memory_data();
  auto& isolates = shared_data->isolates_;
  int free_entry = -1;
  for (size_t i = 0; i < isolates.size(); i++) {
    if (isolates[i] == isolate) return;
    if (isolates[i] == nullptr) free_entry = static_cast<int>(i);
  }
  if (free_entry >= 0)
    isolates[free_entry] = isolate;
  else
    isolates.push_back(isolate);
}

void GlobalBackingStoreRegistry::BroadcastSharedWasmMemoryGrow(
    Isolate* isolate, const BackingStore* backing_store) {
  {
    GlobalBackingStoreRegistryImpl* impl = GetGlobalBackingStoreRegistryImpl();
    // The global lock protects the list of isolates per backing store.
    base::MutexGuard scope_lock(&impl->mutex_);
    SharedWasmMemoryData* shared_data =
        backing_store->get_shared_wasm_memory_data();
    for (Isolate* other : shared_data->isolates_) {
      if (other == isolate) continue;
      other->stack_guard()->RequestGrowSharedMemory();
    }
  }
  // Update memory objects in this isolate.
  UpdateSharedWasmMemoryObjects(isolate);
}

void GlobalBackingStoreRegistry::UpdateSharedWasmMemoryObjects(
    Isolate* isolate) {

  HandleScope scope(isolate);
  DirectHandle<WeakArrayList> shared_wasm_memories =
      isolate->factory()->shared_wasm_memories();

  for (int i = 0, e = shared_wasm_memories->length(); i < e; ++i) {
    Tagged<HeapObject> obj;
    if (!shared_wasm_memories->Get(i).GetHeapObject(&obj)) continue;

    DirectHandle<WasmMemoryObject> memory_object(Cast<WasmMemoryObject>(obj),
                                                 isolate);
    DirectHandle<JSArrayBuffer> old_buffer(memory_object->array_buffer(),
                                           isolate);
    std::shared_ptr<BackingStore> backing_store = old_buffer->GetBackingStore();
    // Wasm memory always has a BackingStore.
    CHECK_NOT_NULL(backing_store);
    CHECK(backing_store->is_wasm_memory());
    CHECK(backing_store->is_shared());

    // Keep a raw pointer to the backing store for a CHECK later one. Make it
    // {void*} so we do not accidentally try to use it for anything else.
    void* expected_backing_store = backing_store.get();

    DirectHandle<JSArrayBuffer> new_buffer =
        isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store));
    CHECK_EQ(expected_backing_store, new_buffer->GetBackingStore().get());
    memory_object->SetNewBuffer(*new_buffer);
  }
}
#endif  // V8_ENABLE_WEBASSEMBLY

}  // namespace v8::internal

#undef TRACE_BS
```