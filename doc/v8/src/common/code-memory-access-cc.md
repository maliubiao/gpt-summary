Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding and Core Purpose:**

The first step is to read the file header and the namespace. It immediately tells us this code is part of V8 (Google's JavaScript engine) and likely deals with memory access, specifically related to code. The presence of `ThreadIsolation` in the namespace hints at thread safety and potentially memory protection mechanisms.

**2. Identifying Key Concepts and Data Structures:**

As we read through the code, certain names and structures jump out:

* **`RwxMemoryWriteScope`:** This strongly suggests a mechanism for controlling write access to memory that is potentially executable (Read, Write, Execute). The "Scope" part indicates a RAII (Resource Acquisition Is Initialization) pattern, where write permissions are acquired when an object of this class is created and released when it's destroyed.
* **`ThreadIsolation`:** This is central to the file. It appears to be the class managing the memory isolation. The `trusted_data_` member suggests a separation of trusted and untrusted data or operations.
* **`JitPage` and `JitPageReference`:**  These clearly relate to pages of memory allocated for Just-In-Time (JIT) compiled code. The `Reference` likely provides a way to access and manage a `JitPage`.
* **`JitAllocation`:**  This represents a specific allocation within a `JitPage`.
* **`WritableJitAllocation` and `WritableJumpTablePair`:** These seem to be RAII wrappers that provide temporary write access to JIT allocations and jump tables, respectively.
* **`ThreadIsolatedAllocator`:**  This points to a custom allocator designed for thread isolation.
* **`MemoryProtectionKey` (PKU):** The `#if V8_HAS_PKU_JIT_WRITE_PROTECT` blocks indicate the use of Memory Protection Keys (PKU), a hardware feature for fine-grained memory access control.
* **`CFIMetadataWriteScope`:** This likely deals with Control Flow Integrity (CFI) and manages write access to metadata related to it.

**3. Analyzing Functionality by Grouping Related Code:**

Instead of reading line by line, it's more efficient to group related functions and understand their collective purpose:

* **`RwxMemoryWriteScope` and related functions:** Clearly about managing write access, especially in the context of PKU. The `IsPKUWritable()` and `SetDefaultPermissionsForSignalHandler()` functions confirm this. The testing version (`RwxMemoryWriteScopeForTesting`) is also noted.
* **`ThreadIsolation::Enabled()` and `ThreadIsolation::Initialize()`:** These handle the enabling and initialization of the thread isolation mechanism, taking into account flags, PKU support, and thread sanitizers.
* **`ThreadIsolation::ConstructNew()` and `ThreadIsolation::Delete()`:** Custom allocation and deallocation that respects the thread isolation settings.
* **`ThreadIsolation::RegisterJitPage()` and `ThreadIsolation::UnregisterJitPage()`:** Managing the registration and unregistration of JIT code memory pages. The internal logic involving splitting and merging pages becomes apparent here.
* **`ThreadIsolation::LookupJitPage*()` and `ThreadIsolation::TryLookupJitPage*()`:** Functions for finding `JitPage` objects based on memory addresses, including thread-safe and non-thread-safe versions.
* **`ThreadIsolation::RegisterJitAllocation*()` and `ThreadIsolation::LookupJitAllocation*()`:** Managing allocations *within* the JIT pages.
* **`ThreadIsolation::WriteProtectMemory()` and related PKU code:** Explicitly controlling memory permissions using PKU.
* **`JitPage` and `JitPageReference` methods:**  Detailed operations on individual JIT pages, such as shrinking, expanding, merging, and managing internal allocations. The `CheckForRegionOverlap` function highlights a safety measure.
* **`WritableJitAllocation` and `WritableJumpTablePair`:** RAII wrappers providing temporary write access.

**4. Connecting to JavaScript Functionality (if applicable):**

The key here is to understand that V8 compiles JavaScript code into machine code. Therefore, the memory being managed by this code is where the *compiled* JavaScript lives.

* JIT compilation is the core connection. The `JitPage` represents memory allocated to store this dynamically generated code.
* The `InstructionStream` is a V8 internal representation of the compiled code.
* Jump tables are used in compiled code for efficient branching.

This helps formulate the JavaScript example: a function that gets compiled and executed.

**5. Code Logic Reasoning and Examples:**

For logic involving data structures like the `jit_pages_`, the critical aspect is how lookups, insertions, and deletions work. The use of `std::map` with address as the key is a strong clue. Consider scenarios like:

* Registering a page.
* Looking up an address within a registered page.
* Unregistering a page, potentially splitting existing pages.

This leads to the "Assumptions and Outputs" section with concrete examples.

**6. Identifying Potential Programming Errors:**

Focus on the areas where the code enforces constraints or provides mechanisms for safe access:

* The `RwxMemoryWriteScope` is clearly designed to prevent accidental writes to executable memory. The lack of such a scope when modifying JIT code is a likely error.
* Registering overlapping JIT pages or allocations is another potential issue, which the `CheckForRegionOverlap` function tries to prevent.
* Incorrectly calculating sizes when registering or unregistering memory regions.

**7. Torque Consideration:**

The prompt specifically asks about `.tq` files. Recognizing that Torque is V8's internal language for implementing built-in functions helps answer this part.

**8. Iterative Refinement and Clarity:**

After the initial analysis, review the findings for clarity and accuracy. Organize the information logically, using headings and bullet points. Ensure the explanations are easy to understand, even for someone not deeply familiar with V8 internals. For instance, elaborating on the purpose of RAII for `RwxMemoryWriteScope` adds valuable context.

By following these steps, we can systematically analyze the C++ code and extract its key functionalities, relate it to JavaScript, provide logical examples, and identify common programming errors. The process involves understanding the high-level goals, dissecting the code into logical units, and connecting the pieces to form a comprehensive picture.
The C++ source code file `v8/src/common/code-memory-access.cc` is a crucial component in V8's architecture, responsible for managing and controlling access to memory regions that hold executable code (often referred to as "JIT code"). It introduces a layer of abstraction and protection around these memory areas, especially focusing on scenarios where dynamic code generation and modification occur.

Here's a breakdown of its functionalities:

**1. Thread Isolation and Memory Protection:**

*   **Goal:** The primary goal is to enhance security and stability by isolating JIT-compiled code in memory and controlling write access to it. This is particularly important in the presence of potential security vulnerabilities where untrusted code might attempt to modify or overwrite JIT code.
*   **Mechanism:** It uses mechanisms like Memory Protection Keys (MPK/PKU) on supported architectures (`V8_HAS_PKU_JIT_WRITE_PROTECT`) to restrict write access to JIT code to specific, controlled points in the code. This prevents accidental or malicious modification of executable code.
*   **`ThreadIsolation` Class:**  This class is the central point for managing this isolation. It keeps track of allocated JIT pages and provides methods for registering, unregistering, and looking up these pages and allocations within them.
*   **`RwxMemoryWriteScope` Class:** This class implements a RAII (Resource Acquisition Is Initialization) pattern to temporarily grant write access to JIT memory. When an object of this class is created, it potentially changes the memory protection settings to allow writing. When the object goes out of scope (destructor is called), it restores the original protection settings. This ensures that write access is only granted when explicitly needed and for a limited duration.
*   **`ThreadIsolatedAllocator`:**  While not directly in this file, the code interacts with a `ThreadIsolatedAllocator`. This suggests that the memory for JIT code itself might be allocated using a specialized allocator that works in conjunction with the thread isolation mechanism.

**2. Tracking JIT Code Memory Regions:**

*   **`JitPage` and `JitPageReference`:** The code manages JIT code in terms of "pages" (`JitPage`). The `JitPageReference` provides a way to interact with a `JitPage` object, ensuring thread-safe access through a mutex.
*   **`trusted_data_.jit_pages_`:**  A `std::map` is used to store the registered JIT pages, with the starting address of the page as the key and a pointer to the `JitPage` object as the value.
*   **Registration and Unregistration:**  The `RegisterJitPage` and `UnregisterJitPage` functions allow V8 to inform this module about newly allocated or deallocated memory regions for JIT code. The unregistration process can handle cases where only a portion of a registered page is being freed, potentially splitting the original page.

**3. Managing Allocations within JIT Pages:**

*   **`JitAllocation`:** Represents a specific allocation within a `JitPage`, such as an `InstructionStream` or a jump table. It stores the size and type of the allocation.
*   **`RegisterJitAllocation` and `LookupJitAllocation`:**  Functions to register specific allocations within a JIT page and to look up existing allocations based on their address and size.
*   **Tracking Allocation Types:** The `JitAllocationType` enum allows distinguishing different types of allocations within the JIT code memory.

**4. Providing Writable Access:**

*   **`WritableJitAllocation`:**  Another RAII class similar to `RwxMemoryWriteScope`, but specifically for granting temporary write access to individual JIT allocations. This class uses `RwxMemoryWriteScope` internally.
*   **`WritableJumpTablePair`:**  A specialized RAII class for managing write access to both the main and far jump tables used in WebAssembly.

**5. Control Flow Integrity (CFI) Considerations:**

*   **`CFIMetadataWriteScope`:** This class is used when performing operations that modify metadata related to Control Flow Integrity. CFI is a security mechanism that aims to prevent attackers from hijacking the control flow of the program.

**If `v8/src/common/code-memory-access.cc` ended with `.tq`, it would be a V8 Torque source code file.**

Torque is V8's internal language for implementing built-in JavaScript functions and runtime functionalities. If this file were a Torque file, it would likely contain type definitions and potentially logic related to low-level memory access operations, possibly generated from a higher-level specification. However, since it's a `.cc` file, it's standard C++ code.

**Relationship with JavaScript and Examples:**

This C++ code is fundamental to how V8 executes JavaScript. When JavaScript code is run, V8's JIT compiler (like TurboFan or Crankshaft) generates optimized machine code. This generated code needs to be stored in memory, and this is where `code-memory-access.cc` comes into play.

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

// When this function is called repeatedly, V8's JIT compiler will likely
// compile it into optimized machine code. This machine code will be
// allocated in a JIT code memory region managed by the code in
// v8/src/common/code-memory-access.cc.
let result = add(5, 10);
console.log(result); // Output: 15
```

In this example, the `add` function will eventually be compiled into machine code. The `code-memory-access.cc` code is responsible for:

*   Allocating the memory where the compiled machine code for `add` resides.
*   Potentially setting memory protection to make this region executable but initially non-writable (or writable only under specific scopes).
*   Allowing the JIT compiler to write the generated machine code into this allocated memory, possibly using a `WritableJitAllocation`.
*   Ensuring that other parts of the V8 engine or potentially malicious code cannot arbitrarily modify the compiled code of `add`.

**Code Logic Reasoning and Examples:**

Let's consider the `RegisterJitPage` function:

**Assumption:**  A new region of memory is allocated for JIT code, starting at address `0x1000` with a size of `4096` bytes.

**Input to `RegisterJitPage(0x1000, 4096)`:**

*   `address`: `0x1000`
*   `size`: `4096`

**Code Logic:**

1. A mutex lock is acquired on `trusted_data_.jit_pages_mutex_` to ensure thread safety.
2. `CheckForRegionOverlap` is called to verify that the new region doesn't overlap with any existing registered JIT pages.
3. A new `JitPage` object is dynamically allocated with the given `size`.
4. An entry is added to the `trusted_data_.jit_pages_` map: `trusted_data_.jit_pages_[0x1000] = pointer_to_new_JitPage`.

**Output:**

*   The `trusted_data_.jit_pages_` map now contains an entry mapping the address `0x1000` to the newly created `JitPage` object.

Now, consider the `LookupJitPage` function:

**Assumption:** We want to find the `JitPage` containing the address `0x1500`.

**Input to `LookupJitPage(0x1500, some_size)`:**

*   `addr`: `0x1500`
*   `size`: `some_size` (the exact size is used for boundary checks within the page)

**Code Logic:**

1. A mutex lock is acquired on `trusted_data_.jit_pages_mutex_`.
2. The `trusted_data_.jit_pages_` map is searched for an entry where the key (starting address of the page) is less than or equal to `0x1500`, and the end address of the page (`start_address + page_size`) is greater than `0x1500`.
3. In our example, if the page registered at `0x1000` has a size of `4096`, it covers the range `0x1000` to `0x1FFF`. Since `0x1500` falls within this range, the corresponding `JitPage` is found.

**Output:**

*   A `JitPageReference` object is returned, referring to the `JitPage` that starts at `0x1000`.

**User-Common Programming Errors and How This Code Helps Prevent Them:**

1. **Accidental Writes to Executable Memory:**

    *   **Error:** A common security vulnerability is when a bug in the code allows writing arbitrary data to memory regions containing executable code. This can be exploited by attackers to inject and execute malicious code.
    *   **Prevention:** The `RwxMemoryWriteScope` and `WritableJitAllocation` classes enforce controlled access. Code that needs to modify JIT code *must* explicitly acquire a write scope. Without it, attempts to write to these protected memory regions will likely result in a segmentation fault or other memory protection errors, halting the program and preventing the unintended modification.

    **Example (Illustrative, not actual V8 code):**

    ```c++
    // Without a write scope (potential error if 'jit_code_ptr' points to protected memory)
    memcpy(jit_code_ptr + offset, malicious_data, data_size);

    // Correct way using a write scope
    {
      WritableJitAllocation write_access(jit_code_ptr, size, JitAllocationType::kInstructionStream);
      memcpy(jit_code_ptr + offset, legitimate_data, data_size);
    } // write_access destructor restores the original permissions
    ```

2. **Data Races on JIT Code Management Structures:**

    *   **Error:**  Multiple threads trying to register or unregister JIT pages concurrently without proper synchronization can lead to inconsistent state and crashes.
    *   **Prevention:** The use of mutexes (e.g., `trusted_data_.jit_pages_mutex_`) ensures that access to shared data structures like the `jit_pages_` map is serialized, preventing data races.

3. **Incorrectly Sized Allocations or Lookups:**

    *   **Error:**  If the size provided when registering or looking up a JIT allocation doesn't match the actual allocated size, it can lead to memory corruption or incorrect behavior.
    *   **Prevention:** The code includes checks (e.g., in `LookupJitPageLocked` and within `JitPageReference` methods) to verify sizes and boundaries, helping to catch these discrepancies.

4. **Forgetting to Restore Memory Protections:**

    *   **Error:** If memory protections are changed to allow writing to JIT code but are not restored afterward, it leaves a security hole open.
    *   **Prevention:** The RAII pattern of `RwxMemoryWriteScope` and `WritableJitAllocation` guarantees that memory protections are automatically restored when the scope ends, even if exceptions occur.

In summary, `v8/src/common/code-memory-access.cc` plays a vital role in V8's security and stability by carefully managing access to memory containing executable code. It uses memory protection mechanisms and synchronization primitives to prevent common programming errors and potential security vulnerabilities related to dynamic code generation.

### 提示词
```
这是目录为v8/src/common/code-memory-access.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/code-memory-access.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```