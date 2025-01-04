Response: My thought process to analyze the C++ code and explain its functionality with JavaScript examples goes like this:

1. **Understand the Core Problem:** The file name `code-memory-access.cc` and the presence of terms like "JIT," "executable memory," "write protection," and "thread isolation" immediately suggest the code deals with managing memory regions that hold executable code, especially in a multi-threaded environment where security and preventing accidental modification are crucial. The `#if V8_HAS_PKU_JIT_WRITE_PROTECT` sections further hint at hardware-level memory protection mechanisms.

2. **Identify Key Classes and Structures:** I scan the code for prominent class and struct definitions. `ThreadIsolation`, `RwxMemoryWriteScope`, `JitPage`, and `JitAllocation` stand out. These likely represent the core abstractions for managing and controlling access to code memory.

3. **Analyze `ThreadIsolation`:** This class appears to be central. I note its static methods like `Enabled()`, `Initialize()`, `RegisterJitPage()`, `MakeExecutable()`, `RegisterJitAllocation()`, etc. This suggests it's responsible for global management of code memory regions. The `trusted_data_` member likely holds the central data structures (like the `jit_pages_` map) for tracking these regions. The template methods `ConstructNew` and `Delete` hint at custom allocation strategies when thread isolation is enabled.

4. **Analyze `RwxMemoryWriteScope`:** The name strongly suggests controlling read, write, and execute permissions. The `IsPKUWritable()` and `SetDefaultPermissionsForSignalHandler()` methods, along with the `#if V8_HAS_PKU_JIT_WRITE_PROTECT` conditional compilation, confirm its role in managing memory protection keys. It seems to provide a mechanism to temporarily enable write access to normally read-only/execute-only code memory.

5. **Analyze `JitPage` and `JitAllocation`:** `JitPage` seems to represent a contiguous block of JIT-compiled code in memory. The `allocations_` member (a `std::map`) within `JitPage` suggests that smaller units of allocation (`JitAllocation`) are tracked within each page. `JitAllocationType` likely enumerates different categories of allocations within the JIT code (e.g., instructions, jump tables).

6. **Trace Key Functionality:** I pick a few important functions and mentally trace their execution flow. For example:
    * `RegisterJitPage()`:  This adds a new region of executable memory to the `jit_pages_` map. The `CheckForRegionOverlap()` call emphasizes the importance of preventing conflicting memory regions.
    * `RegisterJitAllocation()`: This registers a specific allocation within a `JitPage`. The checks within `JitPageReference::RegisterAllocation()` ensure the allocation is within the page's bounds and doesn't overlap with existing allocations.
    * `MakeExecutable()`: This function directly manipulates memory permissions using the platform's memory protection mechanisms.
    * `RwxMemoryWriteScope`: I understand this as a RAII (Resource Acquisition Is Initialization) mechanism. Creating an instance grants write access, and the destructor revokes it, ensuring write access is temporary and controlled.

7. **Identify the Connection to JavaScript:** The term "JIT" (Just-In-Time compilation) is the key link to JavaScript. V8, the JavaScript engine, compiles JavaScript code into machine code at runtime for better performance. This compiled code resides in the memory regions managed by this C++ code. The functions managing "InstructionStream" and "Wasm" allocations further solidify this connection.

8. **Formulate the Functional Summary:** Based on the analysis, I summarize the core functionality: managing executable code memory, providing write protection, and facilitating temporary write access.

9. **Create JavaScript Examples:** Now, I need to illustrate how this C++ code relates to JavaScript behavior. I think about common JavaScript operations that involve JIT compilation and memory access:
    * **Function Execution:** When a JavaScript function runs for the first time or frequently, V8 compiles it. This compilation creates machine code stored in the managed memory. I create an example showing a simple function being called multiple times to trigger JIT compilation.
    * **Modifying Compiled Code (Indirectly):**  While JavaScript can't directly modify compiled code, certain debugging or hot-reloading scenarios *might* involve invalidating or replacing compiled code. I craft a conceptual example showing how re-defining a function could, behind the scenes, involve the C++ code unregistering and re-registering memory regions. I emphasize that this is an *internal* mechanism.
    * **WebAssembly:** WebAssembly is another form of executable code that V8 handles. I create an example of loading and running a WebAssembly module, as this directly uses the mechanisms for managing executable memory.

10. **Refine and Clarify:** I review my explanation and examples, ensuring they are clear, concise, and accurate. I add details about the security implications of memory protection and the role of `RwxMemoryWriteScope` in controlled modifications. I also ensure I explicitly state that the JavaScript examples are *conceptual* and illustrate the *underlying* C++ mechanisms.

By following these steps, I can break down the complex C++ code, understand its purpose, and effectively explain its relationship to JavaScript using illustrative examples. The key is to focus on the core concepts, identify the connections to JavaScript runtime behavior, and provide clear, relatable examples.
这是一个C++源代码文件，属于V8 JavaScript引擎的一部分，其主要功能是**管理和控制对JIT（Just-In-Time）编译生成的代码内存的访问，并提供线程隔离机制以增强安全性**。

更具体地说，该文件实现了以下功能：

**1. 线程隔离（Thread Isolation）：**

*   **目的:**  提高安全性，防止不同线程意外或恶意地修改彼此的JIT代码。
*   **机制:**
    *   使用了操作系统的内存保护密钥（Memory Protection Keys, MPK/PKU，如果平台支持 `V8_HAS_PKU_JIT_WRITE_PROTECT`）。
    *   维护了一个全局的 `trusted_data_` 结构，用于存储线程隔离所需的数据，例如分配器和保护密钥。
    *   提供了 `ThreadIsolation::Enabled()` 方法来检查线程隔离是否启用。
    *   使用自定义的分配和释放方法 (`ThreadIsolation::ConstructNew` 和 `ThreadIsolation::Delete`)，以便在启用线程隔离时使用特殊的分配器。
    *   `RwxMemoryWriteScope` 类提供了一种临时的、安全的机制来获取对JIT代码内存的写权限，通常用于代码生成或修改。它利用 MPK 来临时禁用写保护。

**2. JIT 代码内存管理:**

*   **跟踪 JIT 代码页:**
    *   使用 `trusted_data_.jit_pages_` (一个 `std::map`) 来存储已分配的 JIT 代码内存页的地址和大小。
    *   提供了 `RegisterJitPage()` 和 `UnregisterJitPage()` 函数来注册和取消注册 JIT 代码页。
    *   `LookupJitPage()` 和 `TryLookupJitPage()` 用于查找给定地址范围是否属于已注册的 JIT 代码页。
*   **跟踪 JIT 代码块（Allocation）：**
    *   每个 `JitPage` 对象内部维护了一个 `allocations_` (也是一个 `std::map`)，用于跟踪在该页内部分配的更小的代码块。
    *   提供了 `RegisterJitAllocation()` 函数来注册 JIT 代码块，并记录其类型 (`JitAllocationType`)。
    *   `LookupJitAllocation()` 用于查找特定地址和大小的 JIT 代码块。
    *   `UnregisterJitAllocation()` 和 `UnregisterRange()` 用于取消注册 JIT 代码块。
*   **控制内存权限:**
    *   `MakeExecutable()` 函数用于将内存区域设置为可执行。在启用 PKU 的情况下，它还会设置相应的内存保护密钥。
    *   `WriteProtectMemory()` 函数用于移除内存区域的写权限，通常在 JIT 代码生成完成后进行保护。

**3. 与 CFI（Control-Flow Integrity）相关的功能:**

*   虽然代码中没有显式提到 CFI，但通过方法名如 `CFIMetadataWriteScope` 可以推断，该文件也参与了 CFI 的管理，确保程序的控制流按照预期执行，防止恶意代码注入。

**与 JavaScript 的关系及示例:**

该文件直接支持 V8 引擎执行 JavaScript 代码。当 V8 编译 JavaScript 代码时，它会生成机器码，并将这些机器码存储在由 `code-memory-access.cc` 管理的内存区域中。

以下是一些 JavaScript 功能与该 C++ 代码相关的例子：

**例子 1:  函数执行与 JIT 编译**

当 JavaScript 函数首次执行或多次执行后被 V8 认为是“热点代码”时，V8 会使用 JIT 编译器将其编译成机器码。

```javascript
function add(a, b) {
  return a + b;
}

// 第一次调用，可能只是解释执行
console.log(add(1, 2));

// 多次调用后，V8可能会进行JIT编译
for (let i = 0; i < 10000; i++) {
  add(i, i + 1);
}

// 再次调用时，执行的是JIT编译后的机器码
console.log(add(5, 10));
```

在这个过程中，`code-memory-access.cc` 的功能如下：

*   **`RegisterJitPage()`:** 当 V8 需要分配内存来存储 `add` 函数的 JIT 代码时，会调用此函数来注册一块新的可执行内存页。
*   **`RegisterJitAllocation()`:**  会将 `add` 函数的编译后的机器码作为一个 JIT 代码块注册到相应的 `JitPage` 中，类型可能是 `kInstructionStream`。
*   **`MakeExecutable()`:**  会将分配的内存页设置为可执行，以便 CPU 可以执行其中的机器码。
*   **`WriteProtectMemory()`:** 在 JIT 编译完成后，为了安全起见，V8 可能会调用此函数移除对该内存区域的写权限，防止意外修改。

**例子 2:  修改 JIT 代码（通常是 V8 内部操作或在调试/热重载场景）**

虽然 JavaScript 代码本身无法直接修改已编译的机器码，但在某些 V8 内部操作或调试、热重载等场景下，可能需要修改或替换已有的 JIT 代码。

```javascript
// 假设这是一个 V8 内部的调试或热重载机制
// 实际 JavaScript 代码无法直接这样操作
// 但可以想象当热重载一个函数时，V8 需要更新其 JIT 代码

function myFunc() {
  console.log("Original implementation");
}

myFunc();

// ... 一段时间后，代码被修改 ...

function myFunc() {
  console.log("New implementation");
}

myFunc();
```

在这个（概念性的）过程中，`code-memory-access.cc` 可能参与：

*   **`RwxMemoryWriteScope`:**  在需要修改 `myFunc` 的 JIT 代码时，V8 会创建一个 `RwxMemoryWriteScope` 对象，临时获得对包含该代码的内存区域的写权限。
*   **`UnregisterJitAllocation()` 和 `UnregisterJitPage()`:**  可能会先取消注册旧的 JIT 代码块或页面。
*   **再次调用 `RegisterJitPage()` 和 `RegisterJitAllocation()`:** 注册新的编译后的代码。
*   **`WriteProtectMemory()`:**  重新保护修改后的代码内存。

**例子 3:  WebAssembly**

WebAssembly 代码也会被编译成本地机器码执行。

```javascript
// 假设已经加载了一个 WebAssembly 模块
const wasmInstance = // ... 加载的 WebAssembly 实例

wasmInstance.exports.myWasmFunction();
```

当执行 WebAssembly 函数时，`code-memory-access.cc` 也会参与：

*   **`RegisterJitPage()` 和 `RegisterJitAllocation()`:**  注册 WebAssembly 模块编译后的代码所在的内存区域，`JitAllocationType` 可能会是 `kWasmInstructionStream` 或类似的类型。

**总结:**

`v8/src/common/code-memory-access.cc` 是 V8 引擎中一个关键的文件，它负责管理和保护 JIT 编译生成的代码内存。它通过线程隔离和精细的内存权限控制来提高安全性和可靠性，确保 JavaScript 和 WebAssembly 代码能够安全有效地执行。虽然开发者无法直接在 JavaScript 中调用这些 C++ 函数，但这些底层机制是 JavaScript 代码运行的基础。

Prompt: 
```
这是目录为v8/src/common/code-memory-access.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/common/code-memory-access.h"

#include <optional>

#include "src/common/code-memory-access-inl.h"
#include "src/objects/instruction-stream-inl.h"
#include "src/utils/allocation.h"

namespace v8 {
namespace internal {

ThreadIsolation::TrustedData ThreadIsolation::trusted_data_;

#if V8_HAS_PKU_JIT_WRITE_PROTECT

// static
int RwxMemoryWriteScope::memory_protection_key() {
  return ThreadIsolation::pkey();
}

bool RwxMemoryWriteScope::IsPKUWritable() {
  DCHECK(ThreadIsolation::initialized());
  return base::MemoryProtectionKey::GetKeyPermission(ThreadIsolation::pkey()) ==
         base::MemoryProtectionKey::kNoRestrictions;
}

void RwxMemoryWriteScope::SetDefaultPermissionsForSignalHandler() {
  DCHECK(ThreadIsolation::initialized());
  if (!RwxMemoryWriteScope::IsSupported()) return;
  base::MemoryProtectionKey::SetPermissionsForKey(
      ThreadIsolation::pkey(), base::MemoryProtectionKey::kDisableWrite);
}

#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT

RwxMemoryWriteScopeForTesting::RwxMemoryWriteScopeForTesting()
    : RwxMemoryWriteScope("For Testing") {}

RwxMemoryWriteScopeForTesting::~RwxMemoryWriteScopeForTesting() {}

// static
bool ThreadIsolation::Enabled() {
#if V8_HEAP_USE_PKU_JIT_WRITE_PROTECT
  return allocator() != nullptr;
#else
  return false;
#endif
}

// static
template <typename T, typename... Args>
void ThreadIsolation::ConstructNew(T** ptr, Args&&... args) {
  if (Enabled()) {
    *ptr = reinterpret_cast<T*>(trusted_data_.allocator->Allocate(sizeof(T)));
    if (!*ptr) return;
    new (*ptr) T(std::forward<Args>(args)...);
  } else {
    *ptr = new T(std::forward<Args>(args)...);
  }
}

// static
template <typename T>
void ThreadIsolation::Delete(T* ptr) {
  if (Enabled()) {
    ptr->~T();
    trusted_data_.allocator->Free(ptr);
  } else {
    delete ptr;
  }
}

// static
void ThreadIsolation::Initialize(
    ThreadIsolatedAllocator* thread_isolated_allocator) {
#if DEBUG
  trusted_data_.initialized = true;
#endif

  bool enable = thread_isolated_allocator != nullptr && !v8_flags.jitless;

#ifdef THREAD_SANITIZER
  // TODO(sroettger): with TSAN enabled, we get crashes because
  // SetDefaultPermissionsForSignalHandler gets called while a
  // RwxMemoryWriteScope is active. It seems that tsan's ProcessPendingSignals
  // doesn't restore the pkru value after executing the signal handler.
  enable = false;
#endif

#if V8_HAS_PKU_JIT_WRITE_PROTECT
  if (!v8_flags.memory_protection_keys ||
      !base::MemoryProtectionKey::HasMemoryProtectionKeySupport()) {
    enable = false;
  }
#endif

  if (enable) {
    trusted_data_.allocator = thread_isolated_allocator;
#if V8_HAS_PKU_JIT_WRITE_PROTECT
    trusted_data_.pkey = trusted_data_.allocator->Pkey();
#endif
  }

  {
    // We need to allocate the memory for jit page tracking even if we don't
    // enable the ThreadIsolation protections.
    CFIMetadataWriteScope write_scope("Initialize thread isolation.");
    ConstructNew(&trusted_data_.jit_pages_mutex_);
    ConstructNew(&trusted_data_.jit_pages_);
  }

  if (!enable) {
    return;
  }

#if V8_HAS_PKU_JIT_WRITE_PROTECT
  // Check that our compile time assumed page size that we use for padding was
  // large enough.
  CHECK_GE(THREAD_ISOLATION_ALIGN_SZ,
           GetPlatformPageAllocator()->CommitPageSize());

  // TODO(sroettger): make this immutable once there's OS support.
  base::MemoryProtectionKey::SetPermissionsAndKey(
      {reinterpret_cast<Address>(&trusted_data_), sizeof(trusted_data_)},
      v8::PageAllocator::Permission::kRead,
      base::MemoryProtectionKey::kDefaultProtectionKey);
#endif
}

// static
ThreadIsolation::JitPageReference ThreadIsolation::LookupJitPageLocked(
    Address addr, size_t size) {
  trusted_data_.jit_pages_mutex_->AssertHeld();
  std::optional<JitPageReference> jit_page = TryLookupJitPageLocked(addr, size);
  CHECK(jit_page.has_value());
  return std::move(jit_page.value());
}

// static
ThreadIsolation::JitPageReference ThreadIsolation::LookupJitPage(Address addr,
                                                                 size_t size) {
  base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
  return LookupJitPageLocked(addr, size);
}

// static
WritableJitPage ThreadIsolation::LookupWritableJitPage(Address addr,
                                                       size_t size) {
  return WritableJitPage(addr, size);
}

// static
std::optional<ThreadIsolation::JitPageReference>
ThreadIsolation::TryLookupJitPage(Address addr, size_t size) {
  base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
  return TryLookupJitPageLocked(addr, size);
}

// static
std::optional<ThreadIsolation::JitPageReference>
ThreadIsolation::TryLookupJitPageLocked(Address addr, size_t size) {
  trusted_data_.jit_pages_mutex_->AssertHeld();

  Address end = addr + size;
  CHECK_GT(end, addr);

  // upper_bound gives us an iterator to the position after address.
  auto it = trusted_data_.jit_pages_->upper_bound(addr);

  // The previous page should be the one we're looking for.
  if (it == trusted_data_.jit_pages_->begin()) {
    return {};
  }

  it--;

  JitPageReference jit_page(it->second, it->first);

  // If the address is not in the range of the jit page, return.
  if (jit_page.End() <= addr) {
    return {};
  }

  if (jit_page.End() >= end) {
    return jit_page;
  }

  // It's possible that the allocation spans multiple pages, merge them.
  auto to_delete_start = ++it;
  for (; jit_page.End() < end && it != trusted_data_.jit_pages_->end(); it++) {
    {
      JitPageReference next_page(it->second, it->first);
      CHECK_EQ(next_page.Address(), jit_page.End());
      jit_page.Merge(next_page);
    }
    Delete(it->second);
  }

  trusted_data_.jit_pages_->erase(to_delete_start, it);

  if (jit_page.End() < end) {
    return {};
  }

  return jit_page;
}

namespace {

size_t GetSize(ThreadIsolation::JitPage* jit_page) {
  return ThreadIsolation::JitPageReference(jit_page, 0).Size();
}

size_t GetSize(ThreadIsolation::JitAllocation allocation) {
  return allocation.Size();
}

template <class T>
void CheckForRegionOverlap(const T& map, Address addr, size_t size) {
  // The data is untrusted from the pov of CFI, so we check that there's no
  // overlaps with existing regions etc.
  CHECK_GE(addr + size, addr);

  // Find an entry in the map with key > addr
  auto it = map.upper_bound(addr);
  bool is_begin = it == map.begin();
  bool is_end = it == map.end();

  // Check for overlap with the next entry
  if (!is_end) {
    Address next_addr = it->first;
    Address offset = next_addr - addr;
    CHECK_LE(size, offset);
  }

  // Check the previous entry for overlap
  if (!is_begin) {
    it--;
    Address prev_addr = it->first;
    const typename T::value_type::second_type& prev_entry = it->second;
    Address offset = addr - prev_addr;
    CHECK_LE(GetSize(prev_entry), offset);
  }
}

template <typename Iterator>
bool AllocationIsBehindRange(Address range_start, Address range_size,
                             const Iterator& it) {
  Address range_end = range_start + range_size;
  Address allocation_start = it->first;
  Address allocation_size = it->second.Size();
  Address allocation_end = allocation_start + allocation_size;

  if (allocation_start >= range_end) return true;

  CHECK_LE(allocation_end, range_end);
  return false;
}

}  // namespace

ThreadIsolation::JitPageReference::JitPageReference(class JitPage* jit_page,
                                                    base::Address address)
    : page_lock_(&jit_page->mutex_), jit_page_(jit_page), address_(address) {}

ThreadIsolation::JitPage::~JitPage() {
  // TODO(sroettger): check that the page is not in use (scan shadow stacks).
}

size_t ThreadIsolation::JitPageReference::Size() const {
  return jit_page_->size_;
}

void ThreadIsolation::JitPageReference::Shrink(class JitPage* tail) {
  jit_page_->size_ -= tail->size_;
  // Move all allocations that are out of bounds.
  auto it = jit_page_->allocations_.lower_bound(End());
  tail->allocations_.insert(it, jit_page_->allocations_.end());
  jit_page_->allocations_.erase(it, jit_page_->allocations_.end());
}

void ThreadIsolation::JitPageReference::Expand(size_t offset) {
  jit_page_->size_ += offset;
}

void ThreadIsolation::JitPageReference::Merge(JitPageReference& next) {
  DCHECK_EQ(End(), next.Address());
  jit_page_->size_ += next.jit_page_->size_;
  next.jit_page_->size_ = 0;
  jit_page_->allocations_.merge(next.jit_page_->allocations_);
  DCHECK(next.jit_page_->allocations_.empty());
}

ThreadIsolation::JitAllocation&
ThreadIsolation::JitPageReference::RegisterAllocation(base::Address addr,
                                                      size_t size,
                                                      JitAllocationType type) {
  // The data is untrusted from the pov of CFI, so the checks are security
  // sensitive.
  CHECK_GE(addr, address_);
  base::Address offset = addr - address_;
  base::Address end_offset = offset + size;
  CHECK_GT(end_offset, offset);
  CHECK_GT(jit_page_->size_, offset);
  CHECK_GE(jit_page_->size_, end_offset);

  CheckForRegionOverlap(jit_page_->allocations_, addr, size);
  return jit_page_->allocations_.emplace(addr, JitAllocation(size, type))
      .first->second;
}

ThreadIsolation::JitAllocation&
ThreadIsolation::JitPageReference::LookupAllocation(base::Address addr,
                                                    size_t size,
                                                    JitAllocationType type) {
  auto it = jit_page_->allocations_.find(addr);
  CHECK_NE(it, jit_page_->allocations_.end());
  CHECK_EQ(it->second.Size(), size);
  CHECK_EQ(it->second.Type(), type);
  return it->second;
}

bool ThreadIsolation::JitPageReference::Contains(base::Address addr,
                                                 size_t size,
                                                 JitAllocationType type) const {
  auto it = jit_page_->allocations_.find(addr);
  return it != jit_page_->allocations_.end() && it->second.Size() == size &&
         it->second.Type() == type;
}

void ThreadIsolation::JitPageReference::UnregisterAllocation(
    base::Address addr) {
  // TODO(sroettger): check that the memory is not in use (scan shadow stacks).
  CHECK_EQ(jit_page_->allocations_.erase(addr), 1);
}

void ThreadIsolation::JitPageReference::UnregisterRange(base::Address start,
                                                        size_t size) {
  auto begin = jit_page_->allocations_.lower_bound(start);
  auto end = begin;
  while (end != jit_page_->allocations_.end() &&
         !AllocationIsBehindRange(start, size, end)) {
    end++;
  }

  // TODO(sroettger): check that the memory is not in use (scan shadow stacks).
  jit_page_->allocations_.erase(begin, end);
}

void ThreadIsolation::JitPageReference::UnregisterAllocationsExcept(
    base::Address start, size_t size, const std::vector<base::Address>& keep) {
  // TODO(sroettger): check that the page is not in use (scan shadow stacks).
  JitPage::AllocationMap keep_allocations;

  auto keep_before = jit_page_->allocations_.lower_bound(start);
  auto keep_after = jit_page_->allocations_.lower_bound(start + size);

  // keep all allocations before the start address.
  if (keep_before != jit_page_->allocations_.begin()) {
    keep_before--;
    keep_allocations.insert(jit_page_->allocations_.begin(), keep_before);
  }

  // from the start address, keep only allocations passed in the vector
  auto keep_iterator = keep.begin();
  for (auto it = keep_before; it != keep_after; it++) {
    if (keep_iterator == keep.end()) break;
    if (it->first == *keep_iterator) {
      keep_allocations.emplace_hint(keep_allocations.end(), it->first,
                                    it->second);
      keep_iterator++;
    }
  }
  CHECK_EQ(keep_iterator, keep.end());

  // keep all allocations after the region
  keep_allocations.insert(keep_after, jit_page_->allocations_.end());

  jit_page_->allocations_.swap(keep_allocations);
}

base::Address ThreadIsolation::JitPageReference::StartOfAllocationAt(
    base::Address inner_pointer) {
  return AllocationContaining(inner_pointer).first;
}

std::pair<base::Address, ThreadIsolation::JitAllocation&>
ThreadIsolation::JitPageReference::AllocationContaining(
    base::Address inner_pointer) {
  auto it = jit_page_->allocations_.upper_bound(inner_pointer);
  CHECK_NE(it, jit_page_->allocations_.begin());
  it--;
  size_t offset = inner_pointer - it->first;
  CHECK_GT(it->second.Size(), offset);
  return {it->first, it->second};
}

// static
void ThreadIsolation::RegisterJitPage(Address address, size_t size) {
  CFIMetadataWriteScope write_scope("Adding new executable memory.");

  base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
  CheckForRegionOverlap(*trusted_data_.jit_pages_, address, size);
  JitPage* jit_page;
  ConstructNew(&jit_page, size);
  trusted_data_.jit_pages_->emplace(address, jit_page);
}

void ThreadIsolation::UnregisterJitPage(Address address, size_t size) {
  // TODO(sroettger): merge the write scopes higher up.
  CFIMetadataWriteScope write_scope("Removing executable memory.");

  JitPage* to_delete;
  {
    base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
    JitPageReference jit_page = LookupJitPageLocked(address, size);

    // We're merging jit pages together, so potentially split them back up
    // if we're only freeing a subrange.

    Address to_free_end = address + size;
    Address jit_page_end = jit_page.Address() + jit_page.Size();

    if (to_free_end < jit_page_end) {
      // There's a tail after the page that we release. Shrink the page and
      // add the tail to the map.
      size_t tail_size = jit_page_end - to_free_end;
      JitPage* tail;
      ConstructNew(&tail, tail_size);
      jit_page.Shrink(tail);
      trusted_data_.jit_pages_->emplace(to_free_end, tail);
    }

    DCHECK_EQ(to_free_end, jit_page.Address() + jit_page.Size());

    if (address == jit_page.Address()) {
      // We remove the start of the region, just remove it from the map.
      to_delete = jit_page.JitPage();
      trusted_data_.jit_pages_->erase(address);
    } else {
      // Otherwise, we need to shrink the region.
      DCHECK_GT(address, jit_page.Address());
      JitPage* tail;
      ConstructNew(&tail, size);
      jit_page.Shrink(tail);
      to_delete = tail;
    }
  }
  Delete(to_delete);
}

// static
bool ThreadIsolation::MakeExecutable(Address address, size_t size) {
  DCHECK(Enabled());

  // TODO(sroettger): ensure that this can only happen at prcoess startup.

#if V8_HAS_PKU_JIT_WRITE_PROTECT
  return base::MemoryProtectionKey::SetPermissionsAndKey(
      {address, size}, PageAllocator::Permission::kReadWriteExecute, pkey());
#else   // V8_HAS_PKU_JIT_WRITE_PROTECT
  UNREACHABLE();
#endif  // V8_HAS_PKU_JIT_WRITE_PROTECT
}

// static
WritableJitAllocation ThreadIsolation::RegisterJitAllocation(
    Address obj, size_t size, JitAllocationType type, bool enforce_write_api) {
  return WritableJitAllocation(
      obj, size, type, WritableJitAllocation::JitAllocationSource::kRegister,
      enforce_write_api);
}

// static
WritableJitAllocation ThreadIsolation::RegisterInstructionStreamAllocation(
    Address addr, size_t size, bool enforce_write_api) {
  return RegisterJitAllocation(
      addr, size, JitAllocationType::kInstructionStream, enforce_write_api);
}

// static
WritableJitAllocation ThreadIsolation::LookupJitAllocation(
    Address addr, size_t size, JitAllocationType type, bool enforce_write_api) {
  return WritableJitAllocation(
      addr, size, type, WritableJitAllocation::JitAllocationSource::kLookup,
      enforce_write_api);
}

// static
WritableJumpTablePair ThreadIsolation::LookupJumpTableAllocations(
    Address jump_table_address, size_t jump_table_size,
    Address far_jump_table_address, size_t far_jump_table_size) {
  return WritableJumpTablePair(jump_table_address, jump_table_size,
                               far_jump_table_address, far_jump_table_size);
}

// static
void ThreadIsolation::RegisterJitAllocations(Address start,
                                             const std::vector<size_t>& sizes,
                                             JitAllocationType type) {
  CFIMetadataWriteScope write_scope("Register bulk allocations.");

  size_t total_size = 0;
  for (auto size : sizes) {
    total_size += size;
  }

  constexpr size_t kSplitThreshold = 0x40000;
  JitPageReference page_ref = total_size >= kSplitThreshold
                                  ? SplitJitPage(start, total_size)
                                  : LookupJitPage(start, total_size);

  for (auto size : sizes) {
    page_ref.RegisterAllocation(start, size, type);
    start += size;
  }
}

void ThreadIsolation::RegisterJitAllocationForTesting(Address obj,
                                                      size_t size) {
  RegisterJitAllocation(obj, size, JitAllocationType::kInstructionStream);
}

// static
void ThreadIsolation::UnregisterJitAllocationForTesting(Address addr,
                                                        size_t size) {
  LookupJitPage(addr, size).UnregisterAllocation(addr);
}

// static
void ThreadIsolation::UnregisterWasmAllocation(Address addr, size_t size) {
  CFIMetadataWriteScope write_scope("UnregisterWasmAllocation");
  LookupJitPage(addr, size).UnregisterAllocation(addr);
}

ThreadIsolation::JitPageReference ThreadIsolation::SplitJitPage(Address addr,
                                                                size_t size) {
  base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
  return SplitJitPageLocked(addr, size);
}

ThreadIsolation::JitPageReference ThreadIsolation::SplitJitPageLocked(
    Address addr, size_t size) {
  trusted_data_.jit_pages_mutex_->AssertHeld();

  JitPageReference jit_page = LookupJitPageLocked(addr, size);

  // Split the JitPage into upto three pages.
  size_t head_size = addr - jit_page.Address();
  size_t tail_size = jit_page.Size() - size - head_size;
  if (tail_size > 0) {
    JitPage* tail;
    ConstructNew(&tail, tail_size);
    jit_page.Shrink(tail);
    trusted_data_.jit_pages_->emplace(addr + size, tail);
  }
  if (head_size > 0) {
    JitPage* mid;
    ConstructNew(&mid, size);
    jit_page.Shrink(mid);
    trusted_data_.jit_pages_->emplace(addr, mid);
    return JitPageReference(mid, addr);
  }

  return jit_page;
}

std::pair<ThreadIsolation::JitPageReference, ThreadIsolation::JitPageReference>
ThreadIsolation::SplitJitPages(Address addr1, size_t size1, Address addr2,
                               size_t size2) {
  if (addr1 > addr2) {
    auto reversed_pair = SplitJitPages(addr2, size2, addr1, size1);
    return {std::move(reversed_pair.second), std::move(reversed_pair.first)};
  }
  // Make sure there's no overlap. SplitJitPageLocked will do additional checks
  // that the sizes don't overflow.
  CHECK_LE(addr1 + size1, addr2);

  base::MutexGuard guard(trusted_data_.jit_pages_mutex_);
  return {SplitJitPageLocked(addr1, size1), SplitJitPageLocked(addr2, size2)};
}

// static
std::optional<Address> ThreadIsolation::StartOfJitAllocationAt(
    Address inner_pointer) {
  CFIMetadataWriteScope write_scope("StartOfJitAllocationAt");
  std::optional<JitPageReference> page = TryLookupJitPage(inner_pointer, 1);
  if (!page) {
    return {};
  }
  return page->StartOfAllocationAt(inner_pointer);
}

// static
bool ThreadIsolation::WriteProtectMemory(
    Address addr, size_t size, PageAllocator::Permission page_permissions) {
  if (!Enabled()) {
    return true;
  }

#if V8_HEAP_USE_PKU_JIT_WRITE_PROTECT
  return base::MemoryProtectionKey::SetPermissionsAndKey(
      {addr, size}, PageAllocator::Permission::kNoAccess,
      ThreadIsolation::pkey());
#else
  UNREACHABLE();
#endif
}

namespace {

class MutexUnlocker {
 public:
  explicit MutexUnlocker(base::Mutex& mutex) : mutex_(mutex) {
    mutex_.AssertHeld();
  }

  ~MutexUnlocker() {
    mutex_.AssertHeld();
    mutex_.Unlock();
  }

 private:
  base::Mutex& mutex_;
};

}  // namespace

// static
bool ThreadIsolation::CanLookupStartOfJitAllocationAt(Address inner_pointer) {
  CFIMetadataWriteScope write_scope("CanLookupStartOfJitAllocationAt");

  // Try to lock the pages mutex and the mutex of the page itself to prevent
  // potential dead locks. The profiler can try to do a lookup from a signal
  // handler. If that signal handler runs while the thread locked one of these
  // mutexes, it would result in a dead lock.
  bool pages_mutex_locked = trusted_data_.jit_pages_mutex_->TryLock();
  if (!pages_mutex_locked) {
    return false;
  }
  MutexUnlocker pages_mutex_unlocker(*trusted_data_.jit_pages_mutex_);

  // upper_bound gives us an iterator to the position after address.
  auto it = trusted_data_.jit_pages_->upper_bound(inner_pointer);

  // The previous page should be the one we're looking for.
  if (it == trusted_data_.jit_pages_->begin()) {
    return {};
  }
  it--;

  JitPage* jit_page = it->second;
  bool jit_page_locked = jit_page->mutex_.TryLock();
  if (!jit_page_locked) {
    return false;
  }
  jit_page->mutex_.Unlock();

  return true;
}

// static
WritableJitAllocation WritableJitAllocation::ForInstructionStream(
    Tagged<InstructionStream> istream) {
  return WritableJitAllocation(
      istream->address(), istream->Size(),
      ThreadIsolation::JitAllocationType::kInstructionStream,
      JitAllocationSource::kLookup);
}

WritableJumpTablePair::WritableJumpTablePair(
    Address jump_table_address, size_t jump_table_size,
    Address far_jump_table_address, size_t far_jump_table_size,
    WritableJumpTablePair::ForTestingTag)
    : write_scope_("for testing"),
      writable_jump_table_(WritableJitAllocation::ForNonExecutableMemory(
          jump_table_address, jump_table_size,
          ThreadIsolation::JitAllocationType::kWasmJumpTable)),
      writable_far_jump_table_(WritableJitAllocation::ForNonExecutableMemory(
          far_jump_table_address, far_jump_table_size,
          ThreadIsolation::JitAllocationType::kWasmFarJumpTable)) {}

// static
WritableJumpTablePair WritableJumpTablePair::ForTesting(
    Address jump_table_address, size_t jump_table_size,
    Address far_jump_table_address, size_t far_jump_table_size) {
  return WritableJumpTablePair(jump_table_address, jump_table_size,
                               far_jump_table_address, far_jump_table_size,
                               ForTestingTag{});
}

template <size_t offset>
void WritableFreeSpace::ClearTagged(size_t count) const {
  base::Address start = address_ + offset;
  // TODO(v8:13355): add validation before the write.
  MemsetTagged(ObjectSlot(start), Tagged<Object>(kClearedFreeMemoryValue),
               count);
}

template void WritableFreeSpace::ClearTagged<kTaggedSize>(size_t count) const;
template void WritableFreeSpace::ClearTagged<2 * kTaggedSize>(
    size_t count) const;

#if DEBUG

// static
void ThreadIsolation::CheckTrackedMemoryEmpty() {
  DCHECK(trusted_data_.jit_pages_->empty());
}

#endif  // DEBUG

}  // namespace internal
}  // namespace v8

"""

```