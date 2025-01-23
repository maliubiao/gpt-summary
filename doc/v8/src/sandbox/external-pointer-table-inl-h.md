Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for Key Identifiers:** The first step is to quickly scan the code for prominent keywords and structures. I see:
    * `#ifndef`, `#define`, `#include`:  This immediately tells me it's a header file. The `_INL_H_` suffix suggests it contains inline function definitions, a common practice in C++ for performance.
    * `namespace v8`, `namespace internal`:  Confirms it's part of the V8 JavaScript engine.
    * `class ExternalPointerTableEntry`, `class ExternalPointerTable`:  These are the core data structures. The names strongly suggest they deal with managing external pointers (pointers to memory outside the V8 heap).
    * `Address`, `ExternalPointerHandle`, `ExternalPointerTag`: These look like custom types used for representing memory addresses and identifying external pointers.
    * `Payload`: This likely encapsulates the actual data stored in the table entries.
    * `MakeExternalPointerEntry`, `GetExternalPointer`, `SetExternalPointer`, `ExchangeExternalPointer`, `MakeZappedEntry`, `MakeFreelistEntry`, `Mark`, `Evacuate`: These are the main operations on the entries, giving clues about the table's lifecycle and purpose.
    * `AllocateEntry`, `FreeEntry`, `SweepAndCompact`:  These are operations on the `ExternalPointerTable` itself, indicating memory management within the table.
    * `ManagedResource`: This suggests the table might be involved in managing the lifecycle of external resources.
    * `DCHECK`, `CHECK`, `DCHECK_EQ`, `DCHECK_NE`, `DCHECK_LE`: These are debugging assertions, indicating important invariants and assumptions.
    * `std::atomic`:  Indicates thread-safe operations.
    * `#ifdef V8_COMPRESS_POINTERS`: Conditional compilation, suggesting different behavior based on a build flag.

2. **Understanding the Core Data Structures:**

    * **`ExternalPointerTableEntry`**: The fundamental unit. It seems to hold an `Address` (the actual external pointer) and an `ExternalPointerTag` (metadata). The `Payload` member likely uses bit manipulation to store both efficiently. The presence of `MakeZappedEntry` and `MakeFreelistEntry` suggests a mechanism for managing unused entries. The `Mark` and `Evacuate` functions point towards garbage collection or memory compaction.

    * **`ExternalPointerTable`**: A container for `ExternalPointerTableEntry` objects. It provides methods for allocating, accessing, modifying, and freeing entries. The `Space` nested class suggests the table is organized into different memory regions or arenas.

3. **Inferring Functionality from Methods:**

    * **Allocation and Deallocation:**  `AllocateEntry`, `MakeExternalPointerEntry`, `MakeZappedEntry`, `MakeFreelistEntry` clearly deal with the lifecycle of entries. The freelist suggests a way to reuse freed entries efficiently.

    * **Access and Modification:** `GetExternalPointer`, `SetExternalPointer`, `ExchangeExternalPointer` are the basic accessors and mutators. The `tag` parameter is important for type safety or identification.

    * **Garbage Collection/Compaction:**  `Mark`, `Evacuate`, `SweepAndCompact`, `MaybeCreateEvacuationEntry` strongly indicate involvement in a garbage collection or memory compaction process. The "evacuation" concept suggests moving live objects to a new location.

    * **Managed Resources:** The `ManagedResource` class and related methods (`TakeOwnershipOfManagedResourceIfNecessary`, `FreeManagedResourceIfPresent`) suggest that the table can manage the lifecycle of external resources associated with the pointers. This is important to prevent leaks.

    * **Thread Safety:** The use of `std::atomic` for `payload_` indicates that access to individual entries needs to be thread-safe, likely because both JavaScript and internal V8 threads might interact with these pointers.

4. **Connecting to JavaScript:** The name "external pointer" strongly suggests a connection to JavaScript's interaction with native code (e.g., through Node.js addons or WebAssembly). JavaScript itself doesn't directly manage raw pointers, but it needs a way to safely interact with native libraries that do. This table likely provides that safe abstraction.

5. **Considering Edge Cases and Potential Errors:**  The `DCHECK` statements are valuable here. They reveal important assumptions:
    * The tag is always masked and has the mark bit set.
    * Certain tags are reserved (`kExternalPointerFreeEntryTag`, `kExternalPointerEvacuationEntryTag`).
    * Handles should be valid.

    Potential user errors could involve:
    * Using the wrong tag when accessing a pointer.
    * Holding onto handles after the associated resource has been freed (though V8 tries to mitigate this with zapping).
    * Incorrectly managing the lifecycle of managed resources, potentially leading to double-frees or leaks.

6. **Addressing Specific Questions:** Now, with a good understanding of the code's purpose, I can address the specific questions in the prompt:

    * **Functionality Summary:** Summarize the key purposes identified in the previous steps.
    * **Torque Source:** Check the file extension (`.inl.h` vs `.tq`).
    * **JavaScript Relationship:** Explain how external pointers relate to JavaScript's interaction with native code and provide a concrete example (like `ArrayBuffer`).
    * **Code Logic Inference:**  Choose a simple method like `GetExternalPointer` or `SetExternalPointer` and illustrate its behavior with example inputs and outputs.
    * **Common Programming Errors:**  Elaborate on the potential errors identified from the `DCHECK`s and the general understanding of pointer management.

7. **Refinement and Organization:**  Finally, organize the findings into a clear and structured answer, using headings and bullet points to improve readability. Ensure the language is precise and avoids jargon where possible. Review the answer for accuracy and completeness.
好的，让我们来分析一下 `v8/src/sandbox/external-pointer-table-inl.h` 这个 V8 源代码文件。

**文件功能概述:**

`v8/src/sandbox/external-pointer-table-inl.h` 文件定义了 `ExternalPointerTableEntry` 和 `ExternalPointerTable` 这两个类的内联函数。这两个类共同实现了一个用于管理外部指针的表格。这个表格主要用于 V8 的沙箱环境中，用于安全地存储和访问指向外部（V8 堆外）资源的指针。

其核心功能可以概括为：

1. **存储外部指针:**  `ExternalPointerTable` 维护着一个条目数组，每个 `ExternalPointerTableEntry` 可以存储一个外部指针的地址和一个相关的标签 (`ExternalPointerTag`)。
2. **类型安全访问:** 通过 `ExternalPointerTag` 来区分不同类型的外部指针，确保以正确的类型访问指针，增强了类型安全性。
3. **生命周期管理:**  `ExternalPointerTable` 参与外部资源的生命周期管理，例如，通过 `ManagedResource` 的机制，当外部资源被垃圾回收时，能够清理相关的表格条目。
4. **支持压缩指针:**  代码被 `#ifdef V8_COMPRESS_POINTERS` 包裹，表明这部分代码是当 V8 使用压缩指针时生效的。压缩指针是一种优化技术，用于减少指针的内存占用。
5. **线程安全:** 使用 `std::atomic` 来存储 `payload_`，表明对外部指针条目的访问是线程安全的。
6. **支持垃圾回收:**  提供了 `Mark` 和 `Evacuate` 等方法，用于支持垃圾回收过程中的标记和疏散操作。
7. **延迟初始化:** 注释中提到了 "lazily-initialized"，暗示了某些条目可能在需要时才被初始化。
8. **LSan 集成:** 提到了 `MaybeUpdateRawPointerForLSan` 和 `#if defined(LEAK_SANITIZER)`，说明与 LeakSanitizer 集成，用于检测内存泄漏。

**关于文件扩展名 `.tq`:**

`v8/src/sandbox/external-pointer-table-inl.h` 的扩展名是 `.h`，而不是 `.tq`。因此，它是一个 **C++ 头文件**，而不是 V8 Torque 源代码。Torque 文件通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例:**

`ExternalPointerTable` 在 V8 中用于管理 JavaScript 与外部资源（通常是 C++ 对象或内存）之间的连接。JavaScript 本身不直接操作原始指针，但 V8 需要一种安全的方式来引用和管理这些外部资源。

一个常见的例子是 `ArrayBuffer` 和 `TypedArray`。当你在 JavaScript 中创建一个 `ArrayBuffer` 并使用 C++ 扩展模块来操作它的底层内存时，`ExternalPointerTable` 就可能被用来存储指向 `ArrayBuffer` 底层内存的指针。

**JavaScript 示例:**

```javascript
// 假设有一个 C++ 扩展模块，它创建了一个外部的缓冲区并返回一个句柄
const addon = require('./my_addon');
const externalBufferHandle = addon.createExternalBuffer(1024); // 假设返回的是一个句柄

// V8 内部可能会将 externalBufferHandle 映射到 ExternalPointerTable 中的一个条目，
// 该条目存储了实际的外部缓冲区地址。

// 当 JavaScript 需要访问这个缓冲区时，V8 会使用这个句柄在 ExternalPointerTable 中查找
// 对应的指针。

// 例如，扩展模块可能提供一个函数来读取外部缓冲区的内容
const value = addon.readExternalBuffer(externalBufferHandle, 0);

// 最终，V8 内部会使用 ExternalPointerTable 中存储的指针来访问实际的外部内存。

// 当 ArrayBuffer 不再被 JavaScript 使用时，垃圾回收器会回收它，
// 同时 V8 也会清理 ExternalPointerTable 中相关的条目，并可能释放外部资源。
```

在这个例子中，`externalBufferHandle` 可以被看作是 `ExternalPointerTable` 中一个条目的索引或句柄。V8 使用这个句柄来间接地访问外部缓冲区，而 JavaScript 代码本身并不直接操作指针。

**代码逻辑推理及假设输入与输出:**

让我们以 `ExternalPointerTableEntry::GetExternalPointer` 方法为例进行推理：

**假设输入:**

* `ExternalPointerTableEntry` 对象 `entry` 的 `payload_` 成员存储了一个指向地址 `0x12345678` 的外部指针，并且 `tag` 为 `kMyExternalPointerTag` (假设其值为 `0b1000`)。
* 调用 `entry.GetExternalPointer(kMyExternalPointerTag)`。

**代码逻辑:**

1. `auto payload = payload_.load(std::memory_order_relaxed);`：从原子变量 `payload_` 中加载当前的值。假设加载到的 `payload` 包含地址 `0x12345678` 和标签 `0b1000`。
2. `DCHECK(payload.ContainsPointer());`:  断言 `payload` 包含一个指针（即，不是 free list 或 zapped 状态）。
3. `return payload.Untag(tag);`:  调用 `Payload::Untag` 方法，该方法会移除 `payload` 中的标签信息，返回原始的地址。

**预期输出:**

函数 `GetExternalPointer` 将返回地址 `0x12345678`。

**涉及用户常见的编程错误:**

1. **使用错误的 Tag 进行访问:**
   ```c++
   // 错误示例
   ExternalPointerTableEntry entry;
   entry.MakeExternalPointerEntry(0x98765432, kMyExternalPointerTag, true);
   Address ptr = entry.GetExternalPointer(kAnotherExternalPointerTag); // 使用了错误的 tag
   ```
   在这种情况下，如果 `Payload::Untag` 的实现依赖于标签匹配，或者 V8 在更高层面上检查了标签，可能会导致错误或未定义的行为。V8 的 `DCHECK` 语句 `DCHECK(index == 0 || at(index).HasExternalPointer(tag));`  旨在在调试版本中捕获这类错误。在 release 版本中，如果标签不匹配，可能会返回一个被标记过的地址，导致后续使用时出现问题。

2. **在资源释放后仍然持有句柄:**
   虽然这个头文件本身不直接处理资源的释放，但如果用户（通常是 V8 内部或扩展模块的开发者）在外部资源被释放后仍然持有 `ExternalPointerHandle` 并尝试访问，那么 `ExternalPointerTable::Get` 方法可能会返回一个无效的指针。V8 的 `Zap` 方法会将对应的条目标记为已删除，以帮助检测这类错误。

3. **并发访问问题 (如果不是正确使用 V8 的 API):**
   虽然 `ExternalPointerTableEntry` 使用 `std::atomic` 提供了基本的线程安全保证，但如果不正确地使用 `ExternalPointerTable` 的 API，例如在没有适当同步的情况下同时修改和访问，仍然可能导致数据竞争。V8 内部会仔细处理这些并发问题。

4. **内存泄漏 (与 `ManagedResource` 相关):**
   如果外部资源被标记为 `ManagedResource`，但其生命周期管理不当，可能会导致内存泄漏。`ExternalPointerTable` 提供了管理 `ManagedResource` 的机制，但最终的正确性取决于资源管理逻辑的实现。

总而言之，`v8/src/sandbox/external-pointer-table-inl.h` 定义了一个关键的机制，用于在 V8 沙箱环境中安全、高效地管理外部指针，连接 JavaScript 代码和底层的 C++ 资源。理解它的功能有助于深入了解 V8 如何与外部世界交互。

### 提示词
```
这是目录为v8/src/sandbox/external-pointer-table-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/sandbox/external-pointer-table-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_SANDBOX_EXTERNAL_POINTER_TABLE_INL_H_
#define V8_SANDBOX_EXTERNAL_POINTER_TABLE_INL_H_

#include "src/sandbox/compactible-external-entity-table-inl.h"
#include "src/sandbox/external-pointer-table.h"
#include "src/sandbox/external-pointer.h"

#ifdef V8_COMPRESS_POINTERS

namespace v8 {
namespace internal {

void ExternalPointerTableEntry::MakeExternalPointerEntry(Address value,
                                                         ExternalPointerTag tag,
                                                         bool mark_as_alive) {
  DCHECK_EQ(0, value & kExternalPointerTagMask);
  DCHECK(tag & kExternalPointerMarkBit);
  DCHECK_NE(tag, kExternalPointerFreeEntryTag);
  DCHECK_NE(tag, kExternalPointerEvacuationEntryTag);

  Payload new_payload(value, tag);
  if (V8_LIKELY(!mark_as_alive)) {
    new_payload.ClearMarkBit();
  }
  payload_.store(new_payload, std::memory_order_relaxed);
  MaybeUpdateRawPointerForLSan(value);
}

Address ExternalPointerTableEntry::GetExternalPointer(
    ExternalPointerTag tag) const {
  auto payload = payload_.load(std::memory_order_relaxed);
  DCHECK(payload.ContainsPointer());
  return payload.Untag(tag);
}

void ExternalPointerTableEntry::SetExternalPointer(Address value,
                                                   ExternalPointerTag tag) {
  DCHECK_EQ(0, value & kExternalPointerTagMask);
  DCHECK(tag & kExternalPointerMarkBit);
  DCHECK(payload_.load(std::memory_order_relaxed).ContainsPointer());

  Payload new_payload(value, tag);
  payload_.store(new_payload, std::memory_order_relaxed);
  MaybeUpdateRawPointerForLSan(value);
}

bool ExternalPointerTableEntry::HasExternalPointer(
    ExternalPointerTag tag) const {
  auto payload = payload_.load(std::memory_order_relaxed);
  if (!payload.ContainsPointer()) return false;
  return tag == kAnyExternalPointerTag || payload.IsTaggedWith(tag);
}

Address ExternalPointerTableEntry::ExchangeExternalPointer(
    Address value, ExternalPointerTag tag) {
  DCHECK_EQ(0, value & kExternalPointerTagMask);
  DCHECK(tag & kExternalPointerMarkBit);

  Payload new_payload(value, tag);
  Payload old_payload =
      payload_.exchange(new_payload, std::memory_order_relaxed);
  DCHECK(old_payload.ContainsPointer());
  MaybeUpdateRawPointerForLSan(value);
  return old_payload.Untag(tag);
}

ExternalPointerTag ExternalPointerTableEntry::GetExternalPointerTag() const {
  auto payload = payload_.load(std::memory_order_relaxed);
  DCHECK(payload.ContainsPointer());
  return payload.ExtractTag();
}

Address ExternalPointerTableEntry::ExtractManagedResourceOrNull() const {
  auto payload = payload_.load(std::memory_order_relaxed);
  ExternalPointerTag tag = payload.ExtractTag();
  if (IsManagedExternalPointerType(tag)) {
    return payload.Untag(tag);
  }
  return kNullAddress;
}

void ExternalPointerTableEntry::MakeZappedEntry() {
  Payload new_payload(kNullAddress, kExternalPointerZappedEntryTag);
  payload_.store(new_payload, std::memory_order_relaxed);
}

void ExternalPointerTableEntry::MakeFreelistEntry(uint32_t next_entry_index) {
  // The next freelist entry is stored in the lower bits of the entry.
  static_assert(kMaxExternalPointers <= std::numeric_limits<uint32_t>::max());
  Payload new_payload(next_entry_index, kExternalPointerFreeEntryTag);
  payload_.store(new_payload, std::memory_order_relaxed);
}

uint32_t ExternalPointerTableEntry::GetNextFreelistEntryIndex() const {
  auto payload = payload_.load(std::memory_order_relaxed);
  return payload.ExtractFreelistLink();
}

void ExternalPointerTableEntry::Mark() {
  auto old_payload = payload_.load(std::memory_order_relaxed);
  DCHECK(old_payload.ContainsPointer());

  auto new_payload = old_payload;
  new_payload.SetMarkBit();

  // We don't need to perform the CAS in a loop: if the new value is not equal
  // to the old value, then the mutator must've just written a new value into
  // the entry. This in turn must've set the marking bit already (see e.g.
  // SetExternalPointer), so we don't need to do it again.
  bool success = payload_.compare_exchange_strong(old_payload, new_payload,
                                                  std::memory_order_relaxed);
  DCHECK(success || old_payload.HasMarkBitSet());
  USE(success);
}

void ExternalPointerTableEntry::MakeEvacuationEntry(Address handle_location) {
  Payload new_payload(handle_location, kExternalPointerEvacuationEntryTag);
  payload_.store(new_payload, std::memory_order_relaxed);
}

bool ExternalPointerTableEntry::HasEvacuationEntry() const {
  auto payload = payload_.load(std::memory_order_relaxed);
  return payload.ContainsEvacuationEntry();
}

void ExternalPointerTableEntry::Evacuate(ExternalPointerTableEntry& dest,
                                         EvacuateMarkMode mode) {
  auto payload = payload_.load(std::memory_order_relaxed);
  // We expect to only evacuate entries containing external pointers.
  DCHECK(payload.ContainsPointer());

  switch (mode) {
    case EvacuateMarkMode::kTransferMark:
      break;
    case EvacuateMarkMode::kLeaveUnmarked:
      DCHECK(!payload.HasMarkBitSet());
      break;
    case EvacuateMarkMode::kClearMark:
      DCHECK(payload.HasMarkBitSet());
      payload.ClearMarkBit();
      break;
  }

  dest.payload_.store(payload, std::memory_order_relaxed);
#if defined(LEAK_SANITIZER)
  dest.raw_pointer_for_lsan_ = raw_pointer_for_lsan_;
#endif  // LEAK_SANITIZER

  // The destination entry takes ownership of the pointer.
  MakeZappedEntry();
}

Address ExternalPointerTable::Get(ExternalPointerHandle handle,
                                  ExternalPointerTag tag) const {
  uint32_t index = HandleToIndex(handle);
#if defined(V8_USE_ADDRESS_SANITIZER)
  // We rely on the tagging scheme to produce non-canonical addresses when an
  // entry isn't tagged with the expected tag. Such "safe" crashes can then be
  // filtered out by our sandbox crash filter. However, when ASan is active, it
  // may perform its shadow memory access prior to the actual memory access.
  // For a non-canonical address, this can lead to a segfault at a _canonical_
  // address, which our crash filter can then not distinguish from a "real"
  // crash. Therefore, in ASan builds, we perform an additional CHECK here that
  // the entry is tagged with the expected tag. The resulting CHECK failure
  // will then be ignored by the crash filter.
  // This check is, however, not needed when accessing the null entry, as that
  // is always valid (it just contains nullptr).
  CHECK(index == 0 || at(index).HasExternalPointer(tag));
#else
  // Otherwise, this is just a DCHECK.
  DCHECK(index == 0 || at(index).HasExternalPointer(tag));
#endif
  return at(index).GetExternalPointer(tag);
}

void ExternalPointerTable::Set(ExternalPointerHandle handle, Address value,
                               ExternalPointerTag tag) {
  DCHECK_NE(kNullExternalPointerHandle, handle);
  uint32_t index = HandleToIndex(handle);
  // TODO(saelo): This works for now, but once we actually free the external
  // object here, this will probably become awkward: it's likely not intuitive
  // that a set_foo() call on some object causes another object to be freed.
  // Probably at that point we should instead just forbid re-setting the
  // external pointers if they are managed (via a DCHECK).
  FreeManagedResourceIfPresent(index);
  TakeOwnershipOfManagedResourceIfNecessary(value, handle, tag);
  at(index).SetExternalPointer(value, tag);
}

Address ExternalPointerTable::Exchange(ExternalPointerHandle handle,
                                       Address value, ExternalPointerTag tag) {
  DCHECK_NE(kNullExternalPointerHandle, handle);
  DCHECK(!IsManagedExternalPointerType(tag));
  uint32_t index = HandleToIndex(handle);
  return at(index).ExchangeExternalPointer(value, tag);
}

ExternalPointerTag ExternalPointerTable::GetTag(
    ExternalPointerHandle handle) const {
  uint32_t index = HandleToIndex(handle);
  return at(index).GetExternalPointerTag();
}

void ExternalPointerTable::Zap(ExternalPointerHandle handle) {
  // Zapping the null entry is a nop. This is useful as we reset the handle of
  // managed resources to the kNullExternalPointerHandle when the entry is
  // deleted. See SweepAndCompact.
  if (handle == kNullExternalPointerHandle) return;
  uint32_t index = HandleToIndex(handle);
  at(index).MakeZappedEntry();
}

ExternalPointerHandle ExternalPointerTable::AllocateAndInitializeEntry(
    Space* space, Address initial_value, ExternalPointerTag tag) {
  DCHECK(space->BelongsTo(this));
  uint32_t index = AllocateEntry(space);
  at(index).MakeExternalPointerEntry(initial_value, tag,
                                     space->allocate_black());
  ExternalPointerHandle handle = IndexToHandle(index);
  TakeOwnershipOfManagedResourceIfNecessary(initial_value, handle, tag);
  return handle;
}

void ExternalPointerTable::Mark(Space* space, ExternalPointerHandle handle,
                                Address handle_location) {
  DCHECK(space->BelongsTo(this));

  // The handle_location must always contain the given handle. Except if the
  // slot is lazily-initialized. In that case, the handle may transition from
  // the null handle to a valid handle. However, in that case the
  // newly-allocated entry will already have been marked as alive during
  // allocation, and so we don't need to do anything here.
#ifdef DEBUG
  ExternalPointerHandle current_handle = base::AsAtomic32::Acquire_Load(
      reinterpret_cast<ExternalPointerHandle*>(handle_location));
  DCHECK(handle == kNullExternalPointerHandle || handle == current_handle);
#endif

  // If the handle is null, it doesn't have an EPT entry; no mark is needed.
  if (handle == kNullExternalPointerHandle) return;

  uint32_t index = HandleToIndex(handle);
  DCHECK(space->Contains(index));

  // If the table is being compacted and the entry is inside the evacuation
  // area, then allocate and set up an evacuation entry for it.
  MaybeCreateEvacuationEntry(space, index, handle_location);

  // Even if the entry is marked for evacuation, it still needs to be marked as
  // alive as it may be visited during sweeping before being evacuation.
  at(index).Mark();
}

void ExternalPointerTable::Evacuate(Space* from_space, Space* to_space,
                                    ExternalPointerHandle handle,
                                    Address handle_location,
                                    EvacuateMarkMode mode) {
  DCHECK(from_space->BelongsTo(this));
  DCHECK(to_space->BelongsTo(this));

  CHECK(IsValidHandle(handle));

  auto handle_ptr = reinterpret_cast<ExternalPointerHandle*>(handle_location);

#ifdef DEBUG
  // Unlike Mark(), we require that the mutator is stopped, so we can simply
  // verify that the location stores the handle with a non-atomic load.
  DCHECK_EQ(handle, *handle_ptr);
#endif

  // If the handle is null, it doesn't have an EPT entry; no evacuation is
  // needed.
  if (handle == kNullExternalPointerHandle) return;

  uint32_t from_index = HandleToIndex(handle);
  DCHECK(from_space->Contains(from_index));
  uint32_t to_index = AllocateEntry(to_space);

  at(from_index).Evacuate(at(to_index), mode);
  ExternalPointerHandle new_handle = IndexToHandle(to_index);

  if (Address addr = at(to_index).ExtractManagedResourceOrNull()) {
    ManagedResource* resource = reinterpret_cast<ManagedResource*>(addr);
    DCHECK_EQ(resource->ept_entry_, handle);
    resource->ept_entry_ = new_handle;
  }

  // Update slot to point to new handle.
  base::AsAtomic32::Relaxed_Store(handle_ptr, new_handle);
}

// static
bool ExternalPointerTable::IsValidHandle(ExternalPointerHandle handle) {
  uint32_t index = handle >> kExternalPointerIndexShift;
  return handle == index << kExternalPointerIndexShift;
}

// static
uint32_t ExternalPointerTable::HandleToIndex(ExternalPointerHandle handle) {
  DCHECK(IsValidHandle(handle));
  uint32_t index = handle >> kExternalPointerIndexShift;
#if defined(LEAK_SANITIZER)
  // When LSan is active, we use "fat" entries that also store the raw pointer
  // to that LSan can find live references. However, we do this transparently:
  // we simply multiply the handle by two so that `(handle >> index_shift) * 8`
  // still produces the correct offset of the entry in the table. However, this
  // is not secure as an attacker could reference the raw pointer instead of
  // the encoded pointer in an entry, thereby bypassing the type checks. As
  // such, this mode must only be used in testing environments. Alternatively,
  // all places that access external pointer table entries must be made aware
  // that the entries are 16 bytes large when LSan is active.
  index /= 2;
#endif  // LEAK_SANITIZER
  DCHECK_LE(index, kMaxExternalPointers);
  return index;
}

// static
ExternalPointerHandle ExternalPointerTable::IndexToHandle(uint32_t index) {
  DCHECK_LE(index, kMaxExternalPointers);
  ExternalPointerHandle handle = index << kExternalPointerIndexShift;
#if defined(LEAK_SANITIZER)
  handle *= 2;
#endif  // LEAK_SANITIZER
  DCHECK_NE(handle, kNullExternalPointerHandle);
  return handle;
}

bool ExternalPointerTable::Contains(Space* space,
                                    ExternalPointerHandle handle) const {
  DCHECK(space->BelongsTo(this));
  return space->Contains(HandleToIndex(handle));
}

void ExternalPointerTable::Space::NotifyExternalPointerFieldInvalidated(
    Address field_address, ExternalPointerTag tag) {
  // We do not currently support invalidating fields containing managed
  // external pointers. If this is ever needed, we would probably need to free
  // the managed object here as we may otherwise fail to do so during sweeping.
  DCHECK(!IsManagedExternalPointerType(tag));
#ifdef DEBUG
  ExternalPointerHandle handle = base::AsAtomic32::Acquire_Load(
      reinterpret_cast<ExternalPointerHandle*>(field_address));
  DCHECK(Contains(HandleToIndex(handle)));
#endif
  AddInvalidatedField(field_address);
}

void ExternalPointerTable::ManagedResource::ZapExternalPointerTableEntry() {
  if (owning_table_) {
    owning_table_->Zap(ept_entry_);
  }
  ept_entry_ = kNullExternalPointerHandle;
}

void ExternalPointerTable::TakeOwnershipOfManagedResourceIfNecessary(
    Address value, ExternalPointerHandle handle, ExternalPointerTag tag) {
  if (IsManagedExternalPointerType(tag) && value != kNullAddress) {
    ManagedResource* resource = reinterpret_cast<ManagedResource*>(value);
    DCHECK_EQ(resource->ept_entry_, kNullExternalPointerHandle);
    resource->owning_table_ = this;
    resource->ept_entry_ = handle;
  }
}

void ExternalPointerTable::FreeManagedResourceIfPresent(uint32_t entry_index) {
  // In the future, this would be where we actually delete the external
  // resource. Currently, the deletion still happens elsewhere, and so here we
  // instead set the resource's handle to the null handle so that the resource
  // does not attempt to zap its entry when it is eventually destroyed.
  if (Address addr = at(entry_index).ExtractManagedResourceOrNull()) {
    ManagedResource* resource = reinterpret_cast<ManagedResource*>(addr);
    DCHECK_EQ(resource->ept_entry_, IndexToHandle(entry_index));
    resource->ept_entry_ = kNullExternalPointerHandle;
  }
}

}  // namespace internal
}  // namespace v8

#endif  // V8_COMPRESS_POINTERS

#endif  // V8_SANDBOX_EXTERNAL_POINTER_TABLE_INL_H_
```